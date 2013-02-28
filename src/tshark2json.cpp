
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#define REGEX_MATCH 0

#define OUTPUT_BUFFER_SIZE  100000
#define INITIAL_BUFFER_SIZE 100000
#define MIN_BUFFER_ROOM     10000
#define BUFFER_GROW         10000

#define APPEND_OUTPUT_BUFFER(str)   pOutputBufferWrite = append(pOutputBufferWrite, str)
#define APPEND_OUTPUT_BUFFER_INT(i) pOutputBufferWrite = appendInt(pOutputBufferWrite, i)
#define APPEND_OUTPUT_BUFFER_JSON_VALUE(str) pOutputBufferWrite = appendJsonValue(pOutputBufferWrite, str)

enum sectionType_t {
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
};

struct threadData_t {
  pthread_t thread;
  pthread_mutex_t lock;
  pthread_mutex_t waitLock;
  pthread_cond_t wait;
  char* buffer;
  int bufferWritePos;
  int bufferSize;
  bool hasWork;
  bool started;
  bool exit;
};

static int g_threadCount = 8;
static threadData_t* g_threadData;
static pthread_mutex_t g_outputLock;
static bool g_verbose = false;
static bool g_outputData = false;

void replace(const char* original, const char* pattern, const char* replacement, char* buffer);
char* append(char* pDest, const char* str);
char* appendJsonValue(char* pDest, char* str);
char* appendInt(char* pDest, int i);
void* thread_worker(void* threadData);
void changeSection(char** ppOutputBufferWrite, sectionType_t *sectionType, sectionType_t newSectionType);

int main(int argc, char* argv[]) {
  regex_t regexFrame;
  int t;
  size_t n;
  ssize_t read;
  regmatch_t pmatch[1];
  int match;
  threadData_t* pThreadData;
  char* pWrite;
  char* pLine;
  char* pNewBuffer;
  char prevData[INITIAL_BUFFER_SIZE];

  while (1) {
    static struct option longOptions[] = {
      {"verbose", no_argument, 0, 'v'},
      {"data", no_argument, 0, 'd'},
      {"threads", required_argument, 0, 't'},
      {0, 0, 0, 0}
    };
    int optionIndex = 0;
    int c = getopt_long(argc, argv, "vdt:", longOptions, &optionIndex);
    if (c == -1) {
      break;
    }

    switch (c) {
      case 'v':
        g_verbose = true;
        break;
      case 'd':
        g_outputData = true;
        break;
      case 't':
        g_threadCount = strtol(optarg, NULL, 10);
        break;
      case '?':
        /* getopt_long already printed an error message. */
        break;
      default:
        printf("bad opt: %c\n", c);
        abort();
    }
  }

  g_threadData = (threadData_t*) malloc(sizeof (threadData_t) * g_threadCount);

  prevData[0] = '\0';
  regcomp(&regexFrame, "Frame [0-9]*:", 0);
  pthread_mutex_init(&g_outputLock, NULL);

  for (t = 0; t < g_threadCount; t++) {
    g_threadData[t].started = false;
    g_threadData[t].exit = false;
    g_threadData[t].hasWork = false;
    g_threadData[t].bufferSize = INITIAL_BUFFER_SIZE;
    g_threadData[t].bufferWritePos = 0;
    g_threadData[t].buffer = (char*) malloc(g_threadData[t].bufferSize);
    pthread_mutex_init(&g_threadData[t].lock, NULL);
    pthread_mutex_init(&g_threadData[t].waitLock, NULL);
    pthread_cond_init(&g_threadData[t].wait, NULL);
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

  // process stdin
  t = 0;
  while (1) {
    pThreadData = &g_threadData[t];
    while (pThreadData->hasWork) {
      t = (t + 1) % g_threadCount;
      pThreadData = &g_threadData[t];
    }
    pthread_mutex_lock(&pThreadData->lock);
    strcpy(pThreadData->buffer, prevData);
    pThreadData->bufferWritePos = strlen(prevData);
    prevData[0] = '\0';
    while (1) {
      n = pThreadData->bufferSize - pThreadData->bufferWritePos;
      if (n < MIN_BUFFER_ROOM) {
        pThreadData->bufferSize += BUFFER_GROW;
        pNewBuffer = (char*) realloc(pThreadData->buffer, pThreadData->bufferSize);
        if (pNewBuffer != NULL) {
          pThreadData->buffer = pNewBuffer;
        } else {
          fprintf(stderr, "ERROR: failed to allocate memory\n");
          read = -1;
          break;
        }
        n = pThreadData->bufferSize - pThreadData->bufferWritePos;
      }
      pWrite = &pThreadData->buffer[pThreadData->bufferWritePos];
      read = getline(&pWrite, &n, stdin);
      if (read == -1) {
        break;
      }
      if (pThreadData->bufferWritePos > 0) {
        pLine = &pThreadData->buffer[pThreadData->bufferWritePos];
        match = regexec(&regexFrame, pLine, 1, pmatch, 0);
        if (match == REGEX_MATCH) {
          strcpy(prevData, pLine);
          *pLine = '\0';
          pThreadData->hasWork = true;
          break;
        }
      }
      pThreadData->bufferWritePos += read;
    }

    pthread_mutex_unlock(&pThreadData->lock);
    pthread_mutex_lock(&pThreadData->waitLock);
    pthread_cond_signal(&pThreadData->wait);
    pthread_mutex_unlock(&pThreadData->waitLock);
    if (read == -1) {
      break;
    }
    t = (t + 1) % g_threadCount;
  }

  // stop threads
  for (t = 0; t < g_threadCount; t++) {
    while (g_threadData[t].hasWork) {
      usleep(1000);
    }
    g_threadData[t].exit = true;
    pthread_mutex_unlock(&g_threadData[t].lock);
  }

  // wait for threads to end
  for (t = 0; t < g_threadCount; t++) {
    pthread_join(g_threadData[t].thread, NULL);
    free(g_threadData[t].buffer);
  }

  regfree(&regexFrame);

  return 0;
}

void* thread_worker(void* threadDataParam) {
  threadData_t* pThreadData = (threadData_t*) threadDataParam;
  char* pOutputBuffer = (char*) malloc(OUTPUT_BUFFER_SIZE);
  char* pOutputBufferWrite;
  char* pLine;
  char* pEndOfLine;
  char* pStart;
  char* pEnd;
  bool error;
  bool sectionMatch;
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

  regcomp(&regexFrame, "^Frame (.*): ([0-9]*) bytes on wire \\([0-9]* bits\\), ([0-9]*) bytes captured \\([0-9]* bits\\)$", REG_EXTENDED);
  regcomp(&regexSectionEthernet, "^Ethernet II, .*$", REG_EXTENDED);
  regcomp(&regexSectionIp, "^Internet Protocol Version .*$", REG_EXTENDED);
  regcomp(&regexSectionTcp, "^Transmission Control Protocol, .*$", REG_EXTENDED);
  regcomp(&regexSectionUdp, "^User Datagram Protocol, .*$", REG_EXTENDED);
  regcomp(&regexSectionDns, "^Domain Name System .*$", REG_EXTENDED);
  regcomp(&regexSectionHttp, "^Hypertext Transfer Protocol.*$", REG_EXTENDED);
  regcomp(&regexSectionFrame, "^Frame \\([0-9]* bytes\\):$", REG_EXTENDED);
  regcomp(&regexSectionReassembledTcp, "^Reassembled TCP \\([0-9]* bytes\\):$", REG_EXTENDED);
  regcomp(&regexSectionUncompressedEntityBody, "^Uncompressed entity body \\([0-9]* bytes\\):$", REG_EXTENDED);
  regcomp(&regexSectionDechunkedEntityBody, "^De-chunked entity body \\([0-9]* bytes\\):$", REG_EXTENDED);
  regcomp(&regexSectionXml, "^eXtensible Markup Language$", REG_EXTENDED);
  regcomp(&regexData, "^([0-9a-fA-F]+)[[:space:]]+([0-9a-fA-F ]+)[[:space:]]+.+$", REG_EXTENDED);

  // IP Regular Expressions
  regcomp(&regexIPSource, "Source: ([0-9]*.[0-9]*.[0-9]*.[0-9]*)", REG_EXTENDED);
  regcomp(&regexIPDest, "Destination: ([0-9]*.[0-9]*.[0-9]*.[0-9]*)", REG_EXTENDED);

  // TCP Regular Expressions
  regcomp(&regexTcpLen, "Len: ([0-9]*)", REG_EXTENDED);
  regcomp(&regexTcpStreamIndex, "\\[Stream index: ([0-9]*)\\]", REG_EXTENDED);
  regcomp(&regexTcpFlags, "Flags:.*\\((.*)\\)", REG_EXTENDED);
  regcomp(&regexTcpSourcePort, "Source port:.*\\(([0-9]*)\\)", REG_EXTENDED);
  regcomp(&regexTcpDestinationPort, "Destination port:.*\\(([0-9]*)\\)", REG_EXTENDED);
  regcomp(&regexTcpSequenceNumber, "Sequence number:[[:space:]]*([0-9]*)", REG_EXTENDED);
  regcomp(&regexTcpAcknowledgmentNumber, "Acknowledgment number:[[:space:]]*([0-9]*)", REG_EXTENDED);

  //HTTP Regular Expressions
  regcomp(&regexHttpUserAgent, "User-Agent:[[:space:]]*(.*)$", REG_EXTENDED);
  regcomp(&regexHttpUri, "Full request URI:[[:space:]]*(.*)$", REG_EXTENDED);
  regcomp(&regexHttpHost, "Host:[[:space:]]*(.*)$", REG_EXTENDED);
  regcomp(&regexHttpMethod, "Request Method:[[:space:]]*(.*)$", REG_EXTENDED);
  regcomp(&regexHttpStatusCode, "Status Code:[[:space:]]*(.*)$", REG_EXTENDED);

  pThreadData->started = true;
  while (!pThreadData->exit) {
    if (pThreadData->hasWork) {
      pthread_mutex_lock(&pThreadData->lock);

      sectionType = SECTION_TYPE_FRAME;
      error = false;
      pOutputBufferWrite = pOutputBuffer;
      pOutputBufferWrite[0] = '\0';
      APPEND_OUTPUT_BUFFER("{");
      lineNumber = 0;
      pLine = pThreadData->buffer;
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
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_UNKNOWN);
          } else if (regexec(&regexSectionEthernet, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_ETHERNET);
          } else if (regexec(&regexSectionIp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_IP);
          } else if (regexec(&regexSectionTcp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_TCP);
          } else if (regexec(&regexSectionUdp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_UDP);
          } else if (regexec(&regexSectionDns, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DNS);
          } else if (regexec(&regexSectionHttp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_HTTP);
          } else if (regexec(&regexSectionFrame, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA);
          } else if (regexec(&regexSectionReassembledTcp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_REASSEMBLED_TCP);
          } else if (regexec(&regexSectionUncompressedEntityBody, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_UNCOMPRESSED_ENTITY_BODY);
          } else if (regexec(&regexSectionDechunkedEntityBody, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_DECHUNKED_ENTITY_BODY);
          } else if (regexec(&regexSectionXml, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionMatch = true;
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA_XML);
          } else if (sectionType == SECTION_TYPE_UNKNOWN && pLine[0] != '\0') {
            if (regexec(&regexData, pLine, nmatch, pmatch, 0) == REGEX_MATCH) {
              changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA);
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
                  APPEND_OUTPUT_BUFFER_JSON_VALUE(pStart);
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
                if (!sectionMatch) {
                  if (regexec(&regexData, pLine, nmatch, pmatch, 0) != REGEX_MATCH) {
                    if (strlen(pLine) == 0) {
                      break;
                    }
                    fprintf(stderr, "ERROR: bad line in data section: %s\n", pLine);
                    error = true;
                    break;
                  }
                  if (g_outputData) {
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
      changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_END);
      APPEND_OUTPUT_BUFFER("}");

      pthread_mutex_lock(&g_outputLock);
      fprintf(stdout, "%s\n", pOutputBuffer);
      fflush(stdout);
      pthread_mutex_unlock(&g_outputLock);

      pThreadData->hasWork = false;
      pthread_mutex_unlock(&pThreadData->lock);
    } else {
      pthread_mutex_lock(&pThreadData->waitLock);
      pthread_cond_wait(&pThreadData->wait, &pThreadData->waitLock);
      pthread_mutex_unlock(&pThreadData->waitLock);
    }
  }

  free(pOutputBuffer);

  return NULL;
}

char* appendJsonValue(char* pDest, char* str) {
  char temp1[10000];
  char temp2[10000];
  replace(str, "\n", "\\n", temp1);
  replace(temp1, "\\", "\\\\", temp2);
  char* result = append(pDest, temp2);
  return result;
}

char* append(char* pDest, const char* str) {
  while (*str) {
    *pDest++ = *str++;
  }
  *pDest = '\0';
  return pDest;
}

char* appendInt(char* pDest, int i) {
  char buffer[100];
  sprintf(buffer, "%d", i);
  strcpy(pDest, buffer);
  return pDest + strlen(buffer);
}

void changeSection(char** ppOutputBufferWrite, sectionType_t *sectionType, sectionType_t newSectionType) {
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

void replace(const char* original, const char* pattern, const char* replacement, char* buffer) {
  size_t const replen = strlen(replacement);
  size_t const patlen = strlen(pattern);
  size_t const orilen = strlen(original);

  const char* oriptr;
  const char* patloc;
  char* retptr = buffer;

  for (oriptr = original; patloc = strstr(oriptr, pattern); oriptr = patloc + patlen) {
    const size_t skplen = patloc - oriptr;
    // copy the section until the occurence of the pattern
    strncpy(retptr, oriptr, skplen);
    retptr += skplen;
    // copy the replacement 
    strncpy(retptr, replacement, replen);
    retptr += replen;
  }
  // copy the rest of the string.
  strcpy(retptr, oriptr);
}