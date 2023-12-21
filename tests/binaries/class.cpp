#include <stdio.h>

class TraitA {};
class TraitB {};

class A {
private:
    int _a;

public:
    virtual ~A() {}
    virtual void Run() { printf("I am A\n"); }
};

template <class TA, class TB>
class B : public A {
private:
    int _b;

public:
    virtual void Run() { printf("I am B\n"); }
};

int main() {
    A* a = new B<TraitA, TraitB>();
    a->Run();
    delete a;
    return 0;
}
