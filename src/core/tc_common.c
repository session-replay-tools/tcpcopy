
#include <xcopy.h>

inline int before(uint32_t seq1, uint32_t seq2)  
{
    return (int) ((uint32_t) (seq1-seq2)) < 0;
}

