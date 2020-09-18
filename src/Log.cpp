#ifndef NDEBUG
#include <iostream>
std::ostream &_debug_cerr = std::cerr;
#else
#include <fstream>
std::ofstream _debug_cerr = std::ofstream{};
#endif
