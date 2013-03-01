
#define _FILE_OFFSET_BITS 64
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/queue.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

#define REGEX_MATCH 0

#define OUTPUT_BUFFER_SIZE  1000000
#define INITIAL_BUFFER_SIZE 100000
#define MIN_BUFFER_ROOM     10000
#define BUFFER_GROW         10000

#define APPEND_OUTPUT_BUFFER(str)   pOutputBufferWrite = append(pOutputBuffer, pOutputBufferWrite, str)
#define APPEND_OUTPUT_BUFFER_INT(i) pOutputBufferWrite = appendInt(pOutputBuffer, pOutputBufferWrite, i)
#define APPEND_OUTPUT_BUFFER_JSON_VALUE(str) pOutputBufferWrite = appendJsonValue(pOutputBuffer, pOutputBufferWrite, str)
#define REGCOMP(reg, str, opts) if(regcomp(reg,str,opts)) { fprintf(stderr, "Could not compile regex: %s\n", str); }

typedef enum {
  SECTION_TYPE_UNKNOWN,
  SECTION_TYPE_FRAME,
  SECTION_TYPE_ETHERNET,
  SECTION_TYPE_IP,
  SECTION_TYPE_TCP,
  SECTION_TYPE_UDP,
  SECTION_TYPE_DNS,
  SECTION_TYPE_HTTP,
  SECTION_TYPE_DATA,
  SECTION_TYPE_DATA_REASSEMBLED_TCP,
  SECTION_TYPE_DATA_UNCOMPRESSED_ENTITY_BODY,
  SECTION_TYPE_DATA_DECHUNKED_ENTITY_BODY,
  SECTION_TYPE_DATA_XML,
  SECTION_TYPE_END
} sectionType_t;

struct buffer_t {
  char* buffer;
  int bufferWritePos;
  int bufferSize;
  LIST_ENTRY(buffer_t) queuePointers;
};

struct threadData_t {
  pthread_t thread;
  struct buffer_t *pBuffer;
  bool started;
};

static int g_threadCount = 8;
static struct threadData_t* g_threadData;
static pthread_mutex_t g_outputLock;
static bool g_verbose = false;
static bool g_outputData = false;
static bool g_outputUdp = true;
static bool g_outputTcp = true;
static bool g_outputReassembledTcp = true;
static LIST_HEAD(g_unusedBufferQueueHead, buffer_t) g_unusedBufferQueue;
static LIST_HEAD(g_usedBufferQueueHead, buffer_t) g_usedBufferQueue;
static pthread_mutex_t g_usedBufferLock;
static pthread_cond_t g_usedBufferSignal;
static pthread_mutex_t g_unusedBufferLock;
static pthread_cond_t g_unusedBufferSignal;
static bool g_exit = false;
static long g_totalBytesProcessed = 0;

void escape(char* dest, int destSize, const char* src);
char* append(const char* pStart, char* pDest, const char* str);
char* appendJsonValue(const char* pStart, char* pDest, char* str);
char* appendInt(const char* pStart, char* pDest, long i);
void* thread_worker(void* threadData);
void changeSection(const char* pOutputBuffer, char** ppOutputBufferWrite, sectionType_t *sectionType, sectionType_t newSectionType);
void printHelp();
void unusedBufferQueuePush(struct buffer_t* pBuffer);
struct buffer_t* unusedBufferQueuePop();
void usedBufferQueuePush(struct buffer_t* pBuffer);
struct buffer_t* usedBufferQueuePop();

float timeval_subtract(struct timeval *t2, struct timeval *t1) {
  float diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
  return diff / 1000000.0f;
}

int main(int argc, char* argv[]) {
  int t;
  size_t n;
  ssize_t read;
  int match;
  struct buffer_t* pBuffer;
  char* pWrite;
  char* pLine;
  char* pNewBuffer;
  char prevData[INITIAL_BUFFER_SIZE];
  FILE* input = stdin;
  bool hasWork;
  struct timeval startTime, endTime;

  while (1) {
    static struct option longOptions[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {"data", no_argument, 0, 'd'},
      {"tcpOnly", no_argument, 0, 0},
      {"reassembledTcpOnly", no_argument, 0, 0},
      {"threads", required_argument, 0, 't'},
      {"in", required_argument, 0, 'i'},
      {0, 0, 0, 0}
    };
    int optionIndex = 0;
    int c = getopt_long(argc, argv, "hdt:i:", longOptions, &optionIndex);
    if (c == -1) {
      break;
    }

    switch (c) {
      case 0:
        if (!strcmp(longOptions[optionIndex].name, "tcpOnly")) {
          g_outputTcp = true;
          g_outputUdp = false;
          g_outputReassembledTcp = true;
        } else if (!strcmp(longOptions[optionIndex].name, "reassembledTcpOnly")) {
          g_outputTcp = false;
          g_outputUdp = false;
          g_outputReassembledTcp = true;
        } else {
          fprintf(stderr, "invalid option: %s\n", longOptions[optionIndex].name);
          return 1;
        }
        break;
      case 'h':
        printHelp();
        return 1;
      case 'v':
        g_verbose = true;
        break;
      case 'd':
        g_outputData = true;
        break;
      case 't':
        g_threadCount = strtol(optarg, NULL, 10);
        break;
      case 'i':
        input = fopen(optarg, "r");
        if (input == NULL) {
          fprintf(stderr, "could not open file: %s (%d: %s)\n", optarg, errno, strerror(errno));
          return 1;
        }
        break;
      case '?':
        /* getopt_long already printed an error message. */
        break;
      default:
        fprintf(stderr, "bad opt: %c\n", c);
        return 1;
    }
  }

  g_threadData = (struct threadData_t*) malloc(sizeof (struct threadData_t) * g_threadCount);
  pthread_mutex_init(&g_usedBufferLock, NULL);
  pthread_cond_init(&g_usedBufferSignal, NULL);
  pthread_mutex_init(&g_unusedBufferLock, NULL);
  pthread_cond_init(&g_unusedBufferSignal, NULL);

  LIST_INIT(&g_unusedBufferQueue);
  LIST_INIT(&g_usedBufferQueue);
  for (t = 0; t < g_threadCount * 2; t++) {
    pBuffer = (struct buffer_t*) malloc(sizeof (struct buffer_t));
    pBuffer->bufferSize = INITIAL_BUFFER_SIZE;
    pBuffer->buffer = (char*) malloc(pBuffer->bufferSize);
    pBuffer->bufferWritePos = 0;
    unusedBufferQueuePush(pBuffer);
  }

  prevData[0] = '\0';
  pthread_mutex_init(&g_outputLock, NULL);

  for (t = 0; t < g_threadCount; t++) {
    g_threadData[t].started = false;
    g_threadData[t].pBuffer = NULL;
    pthread_create(&g_threadData[t].thread, NULL, thread_worker, (void*) &g_threadData[t]);
  }

  // wait for threads to start
  do {
    for (t = 0; t < g_threadCount; t++) {
      if (!g_threadData[t].started) {
        usleep(1000);
        break;
      }
    }
  } while (t < g_threadCount);
  usleep(1000);

  gettimeofday(&startTime, NULL);

  // process stdin
  t = 0;
  while (1) {
    pBuffer = unusedBufferQueuePop();

    strcpy(pBuffer->buffer, prevData);
    pBuffer->bufferWritePos = strlen(prevData);
    prevData[0] = '\0';
    while (1) {
      n = pBuffer->bufferSize - pBuffer->bufferWritePos;
      if (n < MIN_BUFFER_ROOM) {
        pBuffer->bufferSize += BUFFER_GROW;
        pNewBuffer = (char*) realloc(pBuffer->buffer, pBuffer->bufferSize);
        if (pNewBuffer != NULL) {
          pBuffer->buffer = pNewBuffer;
        } else {
          fprintf(stderr, "ERROR: failed to allocate memory\n");
          read = -1;
          break;
        }
        n = pBuffer->bufferSize - pBuffer->bufferWritePos;
      }
      pWrite = &pBuffer->buffer[pBuffer->bufferWritePos];
      read = getline(&pWrite, &n, input);
      if (read == -1) {
        break;
      }
      if (pBuffer->bufferWritePos > 0) {
        pLine = &pBuffer->buffer[pBuffer->bufferWritePos];
        // find lines matching "Frame ###:"
        // but not "Frame (###):"
        if (pLine[6] != '(' && pLine[0] == 'F' && !strncmp(pLine, "Frame ", 6)) {
          strcpy(prevData, pLine);
          *pLine = '\0';
          usedBufferQueuePush(pBuffer);
          break;
        }
      }
      pBuffer->bufferWritePos += read;
    }

    if (read == -1) {
      break;
    }
  }

  gettimeofday(&endTime, NULL);

  // wait for threads to finish
  do {
    hasWork = false;
    for (t = 0; t < g_threadCount; t++) {
      if (g_threadData[t].pBuffer) {
        hasWork = true;
      }
    }
    usleep(1000);
  } while (hasWork);

  // signal threads to exit
  g_exit = true;
  pthread_mutex_lock(&g_usedBufferLock);
  pthread_cond_broadcast(&g_usedBufferSignal);
  pthread_mutex_unlock(&g_usedBufferLock);

  // wait for threads to end
  for (t = 0; t < g_threadCount; t++) {
    pthread_join(g_threadData[t].thread, NULL);
  }

  float totalTime = timeval_subtract(&endTime, &startTime);

  fprintf(stderr, "Total bytes processed: %0.2fMB\n", (float) g_totalBytesProcessed / 1024.0f / 1024.0f);
  fprintf(stderr, "Total time: %0.2fs\n", totalTime);
  fprintf(stderr, "Rate: %0.2fMb/s\n", (g_totalBytesProcessed / (totalTime + 0.01)) / 1024.0f / 1024.0f * 8.0f);

  return 0;
}

void* thread_worker(void* threadDataParam) {
  struct threadData_t* pThreadData = (struct threadData_t*) threadDataParam;
  char* pOutputBuffer = (char*) malloc(OUTPUT_BUFFER_SIZE);
  char* pOutputBufferWrite;
  char* pLine;
  char* pEndOfLine;
  char* pStart;
  char* pEnd;
  bool error;
  bool sectionMatch;
  bool isTcp;
  bool isUdp;
  bool isReassembledTcp;
  sectionType_t sectionType;
  regex_t regexFrame;
  regex_t regexSectionEthernet;
  regex_t regexSectionIp;
  regex_t regexSectionTcp;
  regex_t regexSectionUdp;
  regex_t regexSectionDns;
  regex_t regexSectionHttp;
  regex_t regexSectionFrame;
  regex_t regexSectionReassembledTcp;
  regex_t regexSectionUncompressedEntityBody;
  regex_t regexSectionDechunkedEntityBody;
  regex_t regexSectionXml;
  regex_t regexData;
  regex_t regexIPSource;
  regex_t regexIPDest;
  regex_t regexTcpLen;
  regex_t regexTcpStreamIndex;
  regex_t regexTcpFlags;
  regex_t regexTcpSourcePort;
  regex_t regexTcpDestinationPort;
  regex_t regexTcpSequenceNumber;
  regex_t regexTcpAcknowledgmentNumber;
  regex_t regexHttpUserAgent;
  regex_t regexHttpUri;
  regex_t regexHttpHost;
  regex_t regexHttpMethod;
  regex_t regexHttpStatusCode;

  size_t nmatch = 10;
  regmatch_t pmatch[10];
  int match;
  int lineNumber;
  int dataAddress;

  REGCOMP(&regexFrame, "^Frame (.*): ([0-9]*) bytes on wire \\([0-9]* bits\\), ([0-9]*) bytes captured \\([0-9]* bits\\)$", REG_EXTENDED);
  REGCOMP(&regexSectionEthernet, "^Ethernet II, .*$", REG_EXTENDED);
  REGCOMP(&regexSectionIp, "^Internet Protocol Version .*$", REG_EXTENDED);
  REGCOMP(&regexSectionTcp, "^Transmission Control Protocol, .*$", REG_EXTENDED);
  REGCOMP(&regexSectionUdp, "^User Datagram Protocol, .*$", REG_EXTENDED);
  REGCOMP(&regexSectionDns, "^Domain Name System .*$", REG_EXTENDED);
  REGCOMP(&regexSectionHttp, "^Hypertext Transfer Protocol.*$", REG_EXTENDED);
  REGCOMP(&regexSectionFrame, "^Frame \\([0-9]* bytes\\):$", REG_EXTENDED);
  REGCOMP(&regexSectionReassembledTcp, "^Reassembled TCP \\([0-9]* bytes\\):$", REG_EXTENDED);
  REGCOMP(&regexSectionUncompressedEntityBody, "^Uncompressed entity body \\([0-9]* bytes\\):$", REG_EXTENDED);
  REGCOMP(&regexSectionDechunkedEntityBody, "^De-chunked entity body \\([0-9]* bytes\\):$", REG_EXTENDED);
  REGCOMP(&regexSectionXml, "^eXtensible Markup Language$", REG_EXTENDED);
  REGCOMP(&regexData, "^([0-9a-fA-F]+)[[:space:]]+([0-9a-fA-F ]+)[[:space:]]+.+$", REG_EXTENDED);

  // IP Regular Expressions
  REGCOMP(&regexIPSource, "Source: ([0-9]*.[0-9]*.[0-9]*.[0-9]*)", REG_EXTENDED);
  REGCOMP(&regexIPDest, "Destination: ([0-9]*.[0-9]*.[0-9]*.[0-9]*)", REG_EXTENDED);

  // TCP Regular Expressions
  REGCOMP(&regexTcpLen, "Len: ([0-9]*)", REG_EXTENDED);
  REGCOMP(&regexTcpStreamIndex, "\\[Stream index: ([0-9]*)\\]", REG_EXTENDED);
  REGCOMP(&regexTcpFlags, "Flags:.*\\((.*)\\)", REG_EXTENDED);
  REGCOMP(&regexTcpSourcePort, "Source port:.*\\(([0-9]*)\\)", REG_EXTENDED);
  REGCOMP(&regexTcpDestinationPort, "Destination port:.*\\(([0-9]*)\\)", REG_EXTENDED);
  REGCOMP(&regexTcpSequenceNumber, "Sequence number:[[:space:]]*([0-9]*)", REG_EXTENDED);
  REGCOMP(&regexTcpAcknowledgmentNumber, "Acknowledgment number:[[:space:]]*([0-9]*)", REG_EXTENDED);

  //HTTP Regular Expressions
  REGCOMP(&regexHttpUserAgent, "User-Agent:[[:space:]]*(.*)", REG_EXTENDED);
  REGCOMP(&regexHttpUri, "[Full request URI[[:space:]]*[truncated]*:[[:space:]]*(.*)]", REG_EXTENDED);
  REGCOMP(&regexHttpHost, "Host:[[:space:]]*(.*)", REG_EXTENDED);
  REGCOMP(&regexHttpMethod, "Request Method:[[:space:]]*(.*)", REG_EXTENDED);
  REGCOMP(&regexHttpStatusCode, "Status Code:[[:space:]]*(.*)", REG_EXTENDED);

  pThreadData->started = true;
  while (!g_exit) {
    pThreadData->pBuffer = usedBufferQueuePop();
    if (!pThreadData->pBuffer) {
      continue;
    }

    sectionType = SECTION_TYPE_FRAME;
    error = false;
    isTcp = false;
    isUdp = false;
    isReassembledTcp = false;
    pOutputBufferWrite = pOutputBuffer;
    pOutputBufferWrite[0] = '\0';
    APPEND_OUTPUT_BUFFER("{");
    lineNumber = 0;
    pLine = pThreadData->pBuffer->buffer;
    while (*pLine && !error) {
      pEndOfLine = strchr(pLine, '\n');
      *pEndOfLine = '\0';

      if (lineNumber == 0) {
        match = regexec(&regexFrame, pLine, nmatch, pmatch, 0);
        if (match == REGEX_MATCH) {
          pLine[pmatch[1].rm_eo] = '\0';
          pLine[pmatch[2].rm_eo] = '\0';
          pLine[pmatch[3].rm_eo] = '\0';
          APPEND_OUTPUT_BUFFER("\"frameSummary\":{\"frame\":");
          APPEND_OUTPUT_BUFFER(&pLine[pmatch[1].rm_so]);
          APPEND_OUTPUT_BUFFER(",\"bytesOnWire\":");
          APPEND_OUTPUT_BUFFER(&pLine[pmatch[2].rm_so]);
          APPEND_OUTPUT_BUFFER(",\"bytesCaptured\":");
          APPEND_OUTPUT_BUFFER(&pLine[pmatch[3].rm_so]);
          g_totalBytesProcessed += strtol(&pLine[pmatch[3].rm_so], NULL, 10);
          APPEND_OUTPUT_BUFFER("}");
        } else {
          fprintf(stderr, "ERROR: bad frame line: %s\n", pLine);
          error = true;
          break;
        }
      } else { // not line number 0
        sectionMatch = false;
        if (pLine[0] == '\0'
                && sectionType != SECTION_TYPE_DATA
                && sectionType != SECTION_TYPE_DATA_REASSEMBLED_TCP
                && sectionType != SECTION_TYPE_DATA_UNCOMPRESSED_ENTITY_BODY) {
          changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_UNKNOWN);
        } else if (pLine[0] != ' ') {
          if (regexec(&regexSectionEthernet, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_ETHERNET);
          } else if (regexec(&regexSectionIp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_IP);
          } else if (regexec(&regexSectionTcp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            isTcp = true;
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_TCP);
          } else if (regexec(&regexSectionUdp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            isUdp = true;
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_UDP);
          } else if (regexec(&regexSectionDns, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DNS);
          } else if (regexec(&regexSectionHttp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_HTTP);
          } else if (regexec(&regexSectionFrame, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA);
          } else if (regexec(&regexSectionReassembledTcp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            isReassembledTcp = true;
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_REASSEMBLED_TCP);
          } else if (regexec(&regexSectionUncompressedEntityBody, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_UNCOMPRESSED_ENTITY_BODY);
          } else if (regexec(&regexSectionDechunkedEntityBody, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_DECHUNKED_ENTITY_BODY);
          } else if (regexec(&regexSectionXml, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_XML);
          }
        }

        if (g_outputData && sectionType == SECTION_TYPE_UNKNOWN && pLine[0] != '\0') {
          if (regexec(&regexData, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
            changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA);
          }
        }

        if (pLine[0] != '\0') {
          switch (sectionType) {
            case SECTION_TYPE_DATA_DECHUNKED_ENTITY_BODY:
            case SECTION_TYPE_DATA_UNCOMPRESSED_ENTITY_BODY:
            case SECTION_TYPE_DATA_REASSEMBLED_TCP:
            case SECTION_TYPE_DATA_XML:
              // don't need this data
              break;
            case SECTION_TYPE_HTTP:
              if (regexec(&regexHttpUserAgent, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"user_agent\":\"");
                APPEND_OUTPUT_BUFFER_JSON_VALUE(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (regexec(&regexHttpUri, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"uri\":\"");
                APPEND_OUTPUT_BUFFER_JSON_VALUE(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (regexec(&regexHttpHost, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"host\":\"");
                APPEND_OUTPUT_BUFFER_JSON_VALUE(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (regexec(&regexHttpMethod, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"method\":\"");
                APPEND_OUTPUT_BUFFER_JSON_VALUE(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (regexec(&regexHttpStatusCode, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"status_code\":\"");
                APPEND_OUTPUT_BUFFER(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (g_verbose) {
                fprintf(stderr, "http: %s\n", pLine);
              }
              break;
            case SECTION_TYPE_FRAME:
              if (g_verbose) {
                fprintf(stderr, "frame: %s\n", pLine);
              }
              break;
            case SECTION_TYPE_ETHERNET:
              if (g_verbose) {
                fprintf(stderr, "ethernet: %s\n", pLine);
              }
              break;
            case SECTION_TYPE_IP:
              if (regexec(&regexIPSource, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"source\":\"");
                APPEND_OUTPUT_BUFFER(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (regexec(&regexIPDest, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"dest\":\"");
                APPEND_OUTPUT_BUFFER(&pLine[pmatch[1].rm_so]);
                APPEND_OUTPUT_BUFFER("\",");
              } else if (g_verbose) {
                fprintf(stderr, "ip: %s\n", pLine);
              }
              break;
            case SECTION_TYPE_TCP:
              if (regexec(&regexTcpLen, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"dataLength\":");
                APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 10));
                APPEND_OUTPUT_BUFFER(",");
              } else if (regexec(&regexTcpStreamIndex, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"streamIndex\":");
                APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 10));
                APPEND_OUTPUT_BUFFER(",");
              } else if (regexec(&regexTcpFlags, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                if (strstr(pStart, "FIN")) {
                  APPEND_OUTPUT_BUFFER("\"isFIN\":true,");
                }
                if (strstr(pStart, "ACK")) {
                  APPEND_OUTPUT_BUFFER("\"isACK\":true,");
                }
                if (strstr(pStart, "PSH")) {
                  APPEND_OUTPUT_BUFFER("\"isPSH\":true,");
                }
                if (strstr(pStart, "SYN")) {
                  APPEND_OUTPUT_BUFFER("\"isSYN\":true,");
                }
              } else if (regexec(&regexTcpSourcePort, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"sourcePort\":");
                APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 10));
                APPEND_OUTPUT_BUFFER(",");
              } else if (regexec(&regexTcpDestinationPort, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"destPort\":");
                APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 10));
                APPEND_OUTPUT_BUFFER(",");
              } else if (regexec(&regexTcpSequenceNumber, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"seq\":");
                APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 10));
                APPEND_OUTPUT_BUFFER(",");
              } else if (regexec(&regexTcpAcknowledgmentNumber, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
                pStart = &pLine[pmatch[1].rm_so];
                pLine[pmatch[1].rm_eo] = '\0';
                APPEND_OUTPUT_BUFFER("\"ack\":");
                APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 10));
                APPEND_OUTPUT_BUFFER(",");
              } else {
                if (g_verbose) {
                  fprintf(stderr, "tcp: %s\n", pLine);
                }
              }
              break;
            case SECTION_TYPE_UDP:
              if (g_verbose) {
                fprintf(stderr, "udp: %s\n", pLine);
              }
              break;
            case SECTION_TYPE_DNS:
              if (g_verbose) {
                fprintf(stderr, "dns: %s\n", pLine);
              }
              break;
            case SECTION_TYPE_DATA:
              if (g_outputData) {
                if (!sectionMatch) {
                  if (regexec(&regexData, pLine, nmatch, pmatch, 0) != REGEX_MATCH) {
                    if (strlen(pLine) == 0) {
                      break;
                    }
                    fprintf(stderr, "ERROR: bad line in data section: %s\n", pLine);
                    error = true;
                    break;
                  }
                  pLine[pmatch[1].rm_eo] = '\0';
                  pLine[pmatch[2].rm_eo] = '\0';
                  dataAddress = strtol(&pLine[pmatch[1].rm_so], NULL, 16);
                  pStart = &pLine[pmatch[2].rm_so];
                  while (pEnd = strchr(pStart, ' ')) {
                    *pEnd = '\0';
                    if (strlen(pStart) == 0) {
                      break;
                    }
                    APPEND_OUTPUT_BUFFER_INT(strtol(pStart, NULL, 16));
                    APPEND_OUTPUT_BUFFER(",");
                    pStart = pEnd + 1;
                  }
                }
              }
              break;
            default:
              if (g_verbose) {
                fprintf(stderr, "unknown: %s\n", pLine);
              }
              break;
          }
        }
      }

      pLine = pEndOfLine + 1;
      lineNumber++;
    }
    changeSection(pOutputBuffer, &pOutputBufferWrite, &sectionType, SECTION_TYPE_END);
    APPEND_OUTPUT_BUFFER("}");

    if ((g_outputTcp && isTcp) || (g_outputUdp && isUdp) || (g_outputReassembledTcp && isReassembledTcp)) {
      pthread_mutex_lock(&g_outputLock);
      fprintf(stdout, "%s\n", pOutputBuffer);
      fflush(stdout);
      pthread_mutex_unlock(&g_outputLock);
    }

    unusedBufferQueuePush(pThreadData->pBuffer);
    pThreadData->pBuffer = NULL;
  }

  free(pOutputBuffer);

  return NULL;
}

char* appendJsonValue(const char* pStart, char* pDest, char* str) {
  char temp[10000];
  escape(temp, 10000, str);
  return append(pStart, pDest, temp);
}

char* append(const char* pStart, char* pDest, const char* str) {
  while (*str) {
    if (pDest - pStart >= OUTPUT_BUFFER_SIZE) {
      fprintf(stderr, "output buffer too small\n");
      return pDest;
    }
    *pDest++ = *str++;
  }
  *pDest = '\0';
  return pDest;
}

char* appendInt(const char* pStart, char* pDest, long i) {
  char buffer[100];
  int bufferLen;
  sprintf(buffer, "%ld", i);
  bufferLen = strlen(buffer);
  if ((pDest - pStart) + bufferLen >= OUTPUT_BUFFER_SIZE) {
    fprintf(stderr, "output buffer too small\n");
    return pDest;
  }
  strcpy(pDest, buffer);
  return pDest + bufferLen;
}

void changeSection(const char* pOutputBuffer, char** ppOutputBufferWrite, sectionType_t *sectionType, sectionType_t newSectionType) {
  char* pOutputBufferWrite = *ppOutputBufferWrite;

  if (*sectionType == newSectionType) {
    return;
  }

  if (*(pOutputBufferWrite - 1) == ',') {
    pOutputBufferWrite--;
    *pOutputBufferWrite = '\0';
  }

  switch (*sectionType) {
    case SECTION_TYPE_DATA:
      if (g_outputData) {
        APPEND_OUTPUT_BUFFER("]");
      }
      break;
    case SECTION_TYPE_TCP:
    case SECTION_TYPE_HTTP:
    case SECTION_TYPE_IP:
      if (*(pOutputBufferWrite - 1) == ',') {
        pOutputBufferWrite--;
        *pOutputBufferWrite = '\0';
      }
      APPEND_OUTPUT_BUFFER("}");
      break;
  }

  switch (newSectionType) {
    case SECTION_TYPE_DATA:
      if (g_outputData) {
        APPEND_OUTPUT_BUFFER(",\"data\": [");
      }
      break;
    case SECTION_TYPE_TCP:
      APPEND_OUTPUT_BUFFER(",\"tcp\": {");
      break;
    case SECTION_TYPE_IP:
      APPEND_OUTPUT_BUFFER(",\"ip\": {");
      break;
    case SECTION_TYPE_HTTP:
      APPEND_OUTPUT_BUFFER(",\"http\": {");
      break;
  }
  *sectionType = newSectionType;
  *ppOutputBufferWrite = pOutputBufferWrite;
}

void escape(char* dest, int destSize, const char* src) {
  destSize--; // make room for \0
  char* p = dest;
  while (*src) {
    if (p - dest >= destSize) {
      *p++ = '\0';
      return;
    }
    if (*src < ' ' || *src > '~') {
      *p++ = '.';
    }
    {
      switch (*src) {
        case '\\':
        case '"':
          *p++ = '\\';
          *p++ = *src++;
          break;
        default:
          *p++ = *src++;
          break;
      }
    }
  }
  *p++ = '\0';
}

void unusedBufferQueuePush(struct buffer_t* pBuffer) {
  pthread_mutex_lock(&g_unusedBufferLock);
  LIST_INSERT_HEAD(&g_unusedBufferQueue, pBuffer, queuePointers);
  pthread_cond_signal(&g_unusedBufferSignal);
  pthread_mutex_unlock(&g_unusedBufferLock);
}

struct buffer_t* unusedBufferQueuePop() {
  struct buffer_t* pBuffer;

  pthread_mutex_lock(&g_unusedBufferLock);
  pBuffer = LIST_FIRST(&g_unusedBufferQueue);
  if (!pBuffer) {
    pthread_cond_wait(&g_unusedBufferSignal, &g_unusedBufferLock);
    pBuffer = LIST_FIRST(&g_unusedBufferQueue);
  }
  assert(pBuffer != NULL);
  LIST_REMOVE(pBuffer, queuePointers);
  pthread_mutex_unlock(&g_unusedBufferLock);
  return pBuffer;
}

void usedBufferQueuePush(struct buffer_t* pBuffer) {
  pthread_mutex_lock(&g_usedBufferLock);
  LIST_INSERT_HEAD(&g_usedBufferQueue, pBuffer, queuePointers);
  pthread_cond_signal(&g_usedBufferSignal);
  pthread_mutex_unlock(&g_usedBufferLock);
}

struct buffer_t* usedBufferQueuePop() {
  struct buffer_t* pBuffer;

  pthread_mutex_lock(&g_usedBufferLock);
  pBuffer = LIST_FIRST(&g_usedBufferQueue);
  if (!pBuffer) {
    pthread_cond_wait(&g_usedBufferSignal, &g_usedBufferLock);
    pBuffer = LIST_FIRST(&g_usedBufferQueue);
  }
  if (pBuffer != NULL) {
    LIST_REMOVE(pBuffer, queuePointers);
  }
  pthread_mutex_unlock(&g_usedBufferLock);
  return pBuffer;
}

void printHelp() {
  printf("Usage: tshark2json [options]\n");
  printf("\n");
  printf("Options:\n");
  printf("  -h, --help            Print help\n");
  printf("  -v, --verbose         Be verbose\n");
  printf("  -d, --data            Output full data in JSON\n");
  printf("  --tcpOnly             Only output TCP packets\n");
  printf("  --reassembledTcpOnly  Only output reassembled TCP packets\n");
  printf("  -t <count>, --threads=<count>\n");
  printf("                        Number of threads to use\n");
  printf("  -i <file>, --in=<file>\n");
  printf("                        File to read instead of STDOUT\n");
}
