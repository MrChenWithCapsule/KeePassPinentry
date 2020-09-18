#ifndef KEEPASSPINENTRY_LOG_H
#define KEEPASSPINENTRY_LOG_H

#ifndef NDEBUG
#include <iostream>
extern std::ostream &_debug_cerr;
#else
#include <fstream>
extern std::ofstream _debug_cerr;
#endif

#endif
