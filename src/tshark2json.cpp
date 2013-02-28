
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

struct frameInfo_t {
  int frame;
  int bytesOnWire;
  int bytesCaptured;
};

threadData_t g_threadData[WORKER_THREAD_COUNT];
pthread_mutex_t g_outputLock;

char* append(char* pDest, const char* str);
void* thread_worker(void* threadData);

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
#define APPEND_OUTPUT_BUFFER(str) pOutputBufferWrite = append(pOutputBufferWrite, str)
  threadData_t* pThreadData = (threadData_t*) threadDataParam;
  char* pOutputBuffer = (char*) malloc(OUTPUT_BUFFER_SIZE);
  char* pOutputBufferWrite;
  char* pLine;
  char* pEndOfLine;
  regex_t regexFrame;
  size_t nmatch = 10;
  regmatch_t pmatch[10];
  int match;
  int lineNumber;
  frameInfo_t frameInfo;

  //regcomp(&regexFrame, "^Frame (.*): ([0-9]*) bytes on wire \\([0-9]* bits\\), ([0-9]*) bytes captured \\([0-9]* bits\\)", 0);
  regcomp(&regexFrame, "^Frame \\(.*\\): \\([0-9]*\\) bytes on wire ([0-9]* bits), \\([0-9]*\\) bytes captured ([0-9]* bits)$", 0);

  pThreadData->started = true;
  while (!pThreadData->exit) {
    if (pThreadData->hasWork) {
      pthread_mutex_lock(&pThreadData->lock);

      pOutputBufferWrite = pOutputBuffer;
      pOutputBufferWrite[0] = '\0';
      APPEND_OUTPUT_BUFFER("{");
      lineNumber = 0;
      pLine = pThreadData->buffer;
      while (*pLine) {
        pEndOfLine = strchr(pLine, '\n');
        *pEndOfLine = '\0';

        if (lineNumber == 0) {
          match = regexec(&regexFrame, pLine, nmatch, pmatch, 0);
          if (match == REGEX_MATCH) {
            pLine[pmatch[1].rm_eo] = '\0';
            pLine[pmatch[2].rm_eo] = '\0';
            pLine[pmatch[3].rm_eo] = '\0';
            frameInfo.frame = atoi(&pLine[pmatch[1].rm_so]);
            frameInfo.bytesOnWire = atoi(&pLine[pmatch[2].rm_so]);
            frameInfo.bytesCaptured = atoi(&pLine[pmatch[3].rm_so]);
            APPEND_OUTPUT_BUFFER("\"frameSummary\":{\"frame\":");
            APPEND_OUTPUT_BUFFER(&pLine[pmatch[1].rm_so]);
            APPEND_OUTPUT_BUFFER(",\"bytesOnWire\":");
            APPEND_OUTPUT_BUFFER(&pLine[pmatch[2].rm_so]);
            APPEND_OUTPUT_BUFFER(",\"bytesCaptured\":");
            APPEND_OUTPUT_BUFFER(&pLine[pmatch[3].rm_so]);
            APPEND_OUTPUT_BUFFER("}");
          } else {
            fprintf(stderr, "ERROR: bad frame line: %s\n", pLine);
            break;
          }
        }

        pLine = pEndOfLine + 1;
        lineNumber++;
      }
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