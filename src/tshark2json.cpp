
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>

#define REGEX_MATCH 0

#define OUTPUT_BUFFER_SIZE  100000
#define INITIAL_BUFFER_SIZE 1000
#define MIN_BUFFER_ROOM     1000
#define BUFFER_GROW         1000
#define WORKER_THREAD_COUNT 8

#define APPEND_OUTPUT_BUFFER(str)   pOutputBufferWrite = append(pOutputBufferWrite, str)
#define APPEND_OUTPUT_BUFFER_INT(i) pOutputBufferWrite = appendInt(pOutputBufferWrite, i)

enum sectionType_t {
  SECTION_TYPE_FRAME,
  SECTION_TYPE_ETHERNET,
  SECTION_TYPE_IP,
  SECTION_TYPE_TCP,
  SECTION_TYPE_UDP,
  SECTION_TYPE_DNS,
  SECTION_TYPE_HTTP,
  SECTION_TYPE_DATA,
  SECTION_TYPE_END
};

struct threadData_t {
  pthread_t thread;
  pthread_mutex_t lock;
  char* buffer;
  int bufferWritePos;
  int bufferSize;
  bool hasWork;
  bool started;
  bool exit;
};

threadData_t g_threadData[WORKER_THREAD_COUNT];
pthread_mutex_t g_outputLock;

char* append(char* pDest, const char* str);
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

  prevData[0] = '\0';
  regcomp(&regexFrame, "Frame [0-9]*:", 0);
  pthread_mutex_init(&g_outputLock, NULL);

  for (t = 0; t < WORKER_THREAD_COUNT; t++) {
    g_threadData[t].started = false;
    g_threadData[t].exit = false;
    g_threadData[t].hasWork = false;
    g_threadData[t].bufferSize = INITIAL_BUFFER_SIZE;
    g_threadData[t].bufferWritePos = 0;
    g_threadData[t].buffer = (char*) malloc(g_threadData[t].bufferSize);
    pthread_mutex_init(&g_threadData[t].lock, NULL);
    pthread_create(&g_threadData[t].thread, NULL, thread_worker, (void*) &g_threadData[t]);
  }

  do {
    for (t = 0; t < WORKER_THREAD_COUNT; t++) {
      if (!g_threadData[t].started) {
        usleep(1000);
        break;
      }
    }
  } while (t < WORKER_THREAD_COUNT);
  usleep(1000);

  t = 0;
  while (1) {
    pThreadData = &g_threadData[t];
    while (pThreadData->hasWork) {
      usleep(1000);
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
    if (read == -1) {
      break;
    }
    t = (t + 1) % WORKER_THREAD_COUNT;
    break;
  }

  for (t = 0; t < WORKER_THREAD_COUNT; t++) {
    while (g_threadData[t].hasWork) {
      usleep(1000);
    }
    g_threadData[t].exit = true;
    pthread_mutex_unlock(&g_threadData[t].lock);
  }
  for (t = 0; t < WORKER_THREAD_COUNT; t++) {
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
  sectionType_t sectionType;
  regex_t regexFrame;
  regex_t regexSectionEthernet;
  regex_t regexSectionIp;
  regex_t regexSectionTcp;
  regex_t regexSectionUdp;
  regex_t regexSectionDns;
  regex_t regexSectionHttp;
  regex_t regexData;
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
  regcomp(&regexData, "^([0-9a-fA-F]+)[[:space:]]+([0-9a-fA-F ]+)[[:space:]]+.+$", REG_EXTENDED);

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
          if (regexec(&regexSectionEthernet, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionType = SECTION_TYPE_ETHERNET;
          } else if (regexec(&regexSectionIp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionType = SECTION_TYPE_IP;
          } else if (regexec(&regexSectionTcp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionType = SECTION_TYPE_TCP;
          } else if (regexec(&regexSectionUdp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionType = SECTION_TYPE_UDP;
          } else if (regexec(&regexSectionDns, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionType = SECTION_TYPE_DNS;
          } else if (regexec(&regexSectionHttp, pLine, 0, NULL, 0) == REGEX_MATCH) {
            sectionType = SECTION_TYPE_HTTP;
          } else if (strlen(pLine) == 0 && sectionType != SECTION_TYPE_DATA) {
            changeSection(&pOutputBufferWrite, &sectionType, SECTION_TYPE_DATA);
          } else {
            switch (sectionType) {
              case SECTION_TYPE_FRAME:
                fprintf(stderr, "frame: %s\n", pLine);
                break;
              case SECTION_TYPE_ETHERNET:
                fprintf(stderr, "ethernet: %s\n", pLine);
                break;
              case SECTION_TYPE_IP:
                fprintf(stderr, "ip: %s\n", pLine);
                break;
              case SECTION_TYPE_TCP:
                fprintf(stderr, "tcp: %s\n", pLine);
                break;
              case SECTION_TYPE_UDP:
                fprintf(stderr, "udp: %s\n", pLine);
                break;
              case SECTION_TYPE_DNS:
                fprintf(stderr, "dns: %s\n", pLine);
                break;
              case SECTION_TYPE_HTTP:
                fprintf(stderr, "http: %s\n", pLine);
                break;
              case SECTION_TYPE_DATA:
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
                break;
              default:
                fprintf(stderr, "unknown: %s\n", pLine);
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
      usleep(1000);
    }
  }

  free(pOutputBuffer);

  return NULL;
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

  switch (*sectionType) {
    case SECTION_TYPE_DATA:
      if(*(pOutputBufferWrite-1) == ',') {
        pOutputBufferWrite--;
        *pOutputBufferWrite = '\0';
      }
      APPEND_OUTPUT_BUFFER("]");
      break;
  }

  switch (newSectionType) {
    case SECTION_TYPE_DATA:
      APPEND_OUTPUT_BUFFER(",\"data\": [");
      break;
  }
  *sectionType = newSectionType;
  *ppOutputBufferWrite = pOutputBufferWrite;
}