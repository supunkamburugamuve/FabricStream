#include <iostream>

#include "server.h"

using namespace std;

int main() {
    cout << "Hello, World!" << endl;

    RDMAOptions options;
    RDMAServer server(&options);

    return 0;
}
