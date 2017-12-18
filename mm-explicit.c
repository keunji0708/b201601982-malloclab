/*
 * mm-explicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201601982 
 * @name : 김은지	
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* Basic constants and macros */
#define HDRSIZE		4 // header size (bytes)
#define FTRSIZE 	4 // footer size (bytes)
#define WSIZE		4 // Word size (bytes)
#define DSIZE		8 // Double word size (bytes)
#define CHUNKSIZE 	(1<<12) // Extend heap by this amout (bytes)
#define OVERHEAD	8

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) ((unsigned) ((size | alloc)))

/* Read and write a word at address p */
#define GET(p) (*(unsigned *)(p))
#define PUT(p,val) (*(unsigned *)(p) = (unsigned)(val))
#define GET8(p) (*(unsigned long *)(p))
#define PUT8(p,val) (*(unsigned long *)(p) = (unsigned long)(val))

/* Read the size and allocated fields from address p */
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))

#define NEXT_FREEP(bp) ((char *)(bp))
#define PREV_FREEP(bp) ((char *)(bp) + WSIZE)

#define NEXT_FREE_BLKP(bp) ((char *)GET8((char *)(bp)))
#define PREV_FREE_BLKP(bp) ((char *)GET8((char *)(bp) + WSIZE))

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define SIZE_PTR(p) ((size_t *)(((char*)(p)) - SIZE_T_SIZE))

inline void *extend_heap(size_t words);
static void *coalesce(void *ptr);
static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);

static char *h_ptr;
static char *heap_start;
static char *epilogue;

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
    /* Request memory for the initial empty heap */
	// 초기 empty heap을 생성한다.
	if((h_ptr = mem_sbrk(DSIZE + 4 * HDRSIZE)) == NULL)
		return -1;

	heap_start = h_ptr;

	PUT(h_ptr, NULL);
	PUT(h_ptr + WSIZE, NULL);
	PUT(h_ptr + DSIZE, 0); // alignment padding
	PUT(h_ptr + DSIZE + HDRSIZE, PACK(OVERHEAD, 1));
	// prologue header
	PUT(h_ptr + DSIZE + HDRSIZE + FTRSIZE, PACK(OVERHEAD, 1));
	// prologue footer
	PUT(h_ptr + DSIZE + 2 * HDRSIZE + FTRSIZE, PACK(0,1));
	// epilogue header
	/* Root free block의 next와 prev를 생성하고,
	   padding block과 prologue, epilogue를 할당한다. */

	/* Move heap pointer over to footer */
	h_ptr += DSIZE + DSIZE; //heap pointer를footer 위치로 이동시킨다.

    /*Leave room for the previous and next pointers, 
	  place epilogue 3 words down
	 */
	epilogue = h_ptr + HDRSIZE; // epilogue를 초기화한다.

	/* Extend the empty heap with a free block of CHUNKSIZE bytes */
	if(extend_heap(CHUNKSIZE/WSIZE) == NULL)
		return -1; // 사용할 최대 크기의 heap을 미리 할당한다.

	return 0;
}

/*
 * extend_heap
 */
inline void *extend_heap(size_t words){
	unsigned *old_epilogue; // Temp storage for current epilogue
	char *bp; // New block pointer after heap extension
	unsigned size; // Request size for heap memory

	/* Allocate an even number of words to maintain alignment */
	size = (words % 2) ? (words + 1)*WSIZE : words*WSIZE;

	/* Request more memory from heap */
	if((long)(bp = mem_sbrk(size)) < 0)
		return NULL;

	/* Save the old epilogue pointer */
	old_epilogue = epilogue;
	epilogue = bp + size - HDRSIZE; // epilogue가 다음 블록의 header

	/* Write in the header, footer, and new epilogue */
	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	PUT(epilogue, PACK(0, 1));

	return coalesce(bp);
}

/*
 * malloc
 */
void *malloc (size_t size) {
	char *bp; // Block pointer, points to first byte of payload
	unsigned asize; // Block size adjusted for alignment and overhead
	unsigned extendsize; // Amount to extend heap if no fit

	/* size가 올바르지 않을 때 예외처리 */
	if (size == 0)
		return NULL;

	/* block의 크기 결정*/
	if (size <= DSIZE)
		asize = DSIZE + OVERHEAD;
	else
		asize = DSIZE * ((size + DSIZE + (DSIZE-1)) / DSIZE);

	/* 결정한 크기에 알맞은 블록을 list에서 검색하여 해당 위치에 할당*/
	if((bp = find_fit(asize)) != NULL){
		place(bp, asize);
		return bp;
	}
	
	/* free list에서 적절한 블록을 찾지 못했으면 힙을 늘려서 할당*/
	extendsize = MAX(asize, CHUNKSIZE);

	if((bp = extend_heap(extendsize/WSIZE)) == NULL){
		return NULL;
	}
	place(bp, asize);
	return bp;

}

/*
 * free
 */
void free (void *ptr) {
    if(!ptr) // if ptr == 0, 함수를 종료하고 이전 프로시져로 return
		return;
	size_t size = GET_SIZE(HDRP(ptr));
	// ptr의 header에서 block size를 읽어옴

	PUT(HDRP(ptr), PACK(size, 0));
	// ptr의 header에 block size, alloc = 0 저장
	PUT(FTRP(ptr), PACK(size, 0));
	// ptr의 footer에 block size, alloc = 0 저장
	heap_start = coalesce(ptr); // 주위에 빈 블록이 있을 시 병합
}

static void *coalesce(void *ptr){
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(ptr)));
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
	size_t size = GET_SIZE(HDRP(ptr));

	if (prev_alloc && next_alloc){
		return ptr;
	}

	else if (prev_alloc && !next_alloc){
		size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
		PUT(HDRP(ptr), PACK(size, 0));
		PUT(FTRP(ptr), PACK(size, 0));
	}

	else if (!prev_alloc && next_alloc){
		size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
		PUT(FTRP(ptr), PACK(size, 0));
		PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
		ptr = PREV_BLKP(ptr);
	}

	else if (!prev_alloc && !next_alloc){
		size += GET_SIZE(HDRP(PREV_BLKP(ptr)))
			+ GET_SIZE(FTRP(NEXT_BLKP(ptr)));
		PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 0));
		ptr = PREV_BLKP(ptr);
	}
	return ptr;
}

static void *find_fit(size_t asize){
	void *bp;
	for(bp = heap_start; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)){
		if(!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))){
			return bp;
		}
	}
	return NULL; /* No fit */
}


static void place(void *bp, size_t asize){
	size_t csize = GET_SIZE(HDRP(bp));

	if((csize - asize) >= (2 * DSIZE)){
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		bp = NEXT_BLKP(bp);
		PUT(HDRP(bp), PACK(csize - asize, 0));
		PUT(FTRP(bp), PACK(csize - asize, 0));
	}

	else {
		PUT(HDRP(bp), PACK(csize, 1));
		PUT(FTRP(bp), PACK(csize, 1));
	}
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
    size_t oldsize;
	void *newptr;

	/* If size == 0, then this is just free and we return NULL */
	if(size == 0){
		free(oldptr);
		return 0;
	}

	/* If oldptr is NULL, then this is just malloc */
	if(oldptr == NULL){
		return malloc(size);
	}
	
	newptr = malloc(size);

	/* If realloc() fails, the original block is left untouched */
	if(!newptr){
		return 0;
	}

	/* Copy the old data */
	oldsize = *SIZE_PTR(oldptr);
	if(size < oldsize) oldsize = size;
	memcpy(newptr, oldptr, oldsize);

	/* Free the old block */
	free(oldptr);

	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
    size_t bytes = nmemb * size;
	void *newptr;

	newptr = malloc(bytes);
	memset(newptr, 0, bytes);

	return newptr;
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
    return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
    return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}
