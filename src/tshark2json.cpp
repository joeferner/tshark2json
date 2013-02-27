
#include <string>
#include <regex.h>

int main(int argc, char* argv[]) {
  regex_t regexFrame;
  const char* s = "Frame 43: 54 bytes on wire (432 bits), 54 bytes captured (432 bits)";
  
  regcomp(&regexFrame, "Frame [0-9]*:", 0);
  
  size_t nmatch = 2;
  regmatch_t pmatch[2];
  int ret = regexec(&regexFrame, s, nmatch, pmatch, 0);
  if(!ret) {
    printf("match %d\n", ret);
    printf("With the whole expression, "
             "a matched substring \"%.*s\" is found at position %d to %d.\n",
             pmatch[0].rm_eo - pmatch[0].rm_so, &s[pmatch[0].rm_so],
             pmatch[0].rm_so, pmatch[0].rm_eo - 1);
  } else {
    printf("no match %d\n", ret);
  }
  
  regfree(&regexFrame);
  
  return 0;
}
