
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char* argv[]) {
  regex_t regexFrame;
  
  string line;
  size_t n = 1;
  ssize_t read;
  while(getline(cin, line)) {
      n++;
      regcomp(&regexFrame, "Frame [0-9]*:", 0);
  
      size_t nmatch = 2;
      regmatch_t pmatch[2];
      int ret = regexec(&regexFrame, line.c_str(), nmatch, pmatch, 0);
      if(!ret) {
        // printf("match %d\n", ret);
        // printf("With the whole expression, "
        //          "a matched substring \"%.*s\" is found at position %d to %d.\n",
        //          pmatch[0].rm_eo - pmatch[0].rm_so, &line.c_str()[pmatch[0].rm_so],
        //          pmatch[0].rm_so, pmatch[0].rm_eo - 1);
              printf("line: %d %s\n", n, line.c_str());

      } else {
        // printf("no match %d\n", ret);
      }        
  }
  
  
  
  regfree(&regexFrame);
  
  return 0;
}
