#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

// using 17.14 format
typedef int fixed_point;
static int f = 1 << 14;

static inline fixed_point itof(int n)
{
    return n * f;
}

static inline int ftoi(fixed_point x)
{
    return x / f;
}
static inline int ftoi_r(fixed_point x)
{
    if (x >= 0)
        return (x + f / 2) / f;
    else
        return (x - f / 2) / f;
}
static inline fixed_point add_fi(fixed_point x, int n)
{
    return x + n * f;
}
static inline fixed_point sub_fi(fixed_point x, int n)
{
    return x - n * f;
}
static inline fixed_point multi_ff(fixed_point x, fixed_point y)
{
    return ((int64_t)x) * y / f;
}
static inline fixed_point divi_ff(fixed_point x, fixed_point y)
{
    return ((int64_t)x) * f / y;
}
#endif