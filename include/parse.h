#ifndef PARSE_H
#define PARSE_H

#include <iostream>
#include <string>
#include <unistd.h> // for getopt and getopt_long
#include <getopt.h> // for struct option
#include <regex>
#include "scaner.h"

void print_usage();

bool is_valid_scope(const std::string& scope);

void split_scope(const std::string& scope, int& start, int& end);

int main(int argc, char *argv[]) ;


#endif