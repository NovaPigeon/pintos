#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H

#include <stdint.h>
/* 采用 17.14 的浮点表示法，将整形看作 1 位符号，17 位整数，14 位小数的浮点值 */
typedef int fixed_point_t;

/* 小数位数 */
#define FRACTIONAL_NUM 14

/* Convert int to fixed point: n<<14 */
#define INT_TO_FP(N) ((fixed_point_t)(N << FRACTIONAL_NUM))

/* Convert x to integer (rounding toward zero): x/f */
#define FP_TO_INT_ROUND_ZERO(X) ((int)(X >> FRACTIONAL_NUM))

/* Convert x to integer (rounding to nearest):
 * (x + f / 2) / f if x >= 0,
 * (x - f / 2) / f if x <= 0.
 */
#define FP_TO_INT_ROUND_NEAREAST(X) (X >= 0 ? ((X + (1 << (FRACTIONAL_NUM - 1))) >> FRACTIONAL_NUM) \
                                            : ((X - (1 << (FRACTIONAL_NUM - 1))) >> FRACTIONAL_NUM))

/* Add x(fp) and y(fp): x+y */
#define ADD_FF(X, Y) ((fixed_point_t)(X + Y))

/* Subtract y(fp) from x(fp): x - y */
#define SUB_FF(X, Y) ((fixed_point_t)(X - Y))

/* Add x(fp) and n(int): x + n * f */
#define ADD_FI(X, N) ((fixed_point_t)(X + (N << FRACTIONAL_NUM)))

/* Subtract n(int) from x(fp): x - n * f */
#define SUB_FI(X, N) ((fixed_point_t)(X - (N << FRACTIONAL_NUM)))

/* Multiply x(fp) by y(fp): ((int64_t) x) * y) / f */
#define MUL_FF(X,Y) ((fixed_point_t)((((int64_t)X) * Y) >> FRACTIONAL_NUM))

/* Multiply x(fp) by n(int): x*n */
#define MUL_FI(X,N) ((fixed_point_t)(X*N))

/* Divide x(fp) by y(fp): ((int64_t) x) * f / y */
#define DIV_FF(X, Y) ((fixed_point_t)((((int64_t)X) << FRACTIONAL_NUM) / Y))

/* Divide x(fp) by n(int): x/n */
#define DIV_FI(X, N) ((fixed_point_t)(X / N))

#endif /* thread/fixed_point.h */