/*
 * mm-implicit.c - an empty malloc package
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

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define SIZE_PTR(p) ((size_t *)(((char *)(p)) - SIZE_T_SIZE))

/* Basic constants and macros */
#define WSIZE	4 /* Word and header/footer size (bytes) */
#define DSIZE	8 /* Double word size (bytes) */
#define OVERHEAD 8 /* header + footer size */
#define CHUNKSIZE	(1<<12) /* Extend heap by this amount (bytes) */

#define MAX(x, y)	((x) > (y)? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc)	((size) | (alloc))

/* Read and write a word at address p */
#define GET(p)		(*(unsigned int *)(p))
#define PUT(p, val)	(*(unsigned int *)(p) = (val))

/* Read the size and allocated fields from address p */
#define GET_SIZE(p)		(GET(p) & ~0x7)
#define GET_ALLOC(p)	(GET(p) & 0x1)
		
/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp)		((char *)(bp) - WSIZE)
#define FTRP(bp)		((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))

static char *heap_listp = 0;
static void *coalesce(void *ptr);
static void *extend_heap(size_t words);
static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
	/*Create the initial empty heap*/
	if ((heap_listp = mem_sbrk(4*WSIZE)) == NULL)
		// heap_listp = 새로 생성되는 heap 영역의 시작 주소
		return -1; 

	PUT(heap_listp, 0); // 정렬을 위해서 의미없는 값을 삽입
	PUT(heap_listp + WSIZE, PACK(OVERHEAD, 1)); // prologue header
	PUT(heap_listp + DSIZE, PACK(OVERHEAD, 1)); // prologue footer
	PUT(heap_listp + WSIZE + DSIZE, PACK(0, 1)); // epilogue header
	heap_listp += DSIZE;

	/*Extend the empty heap with a free block of CHUNKSIZE bytes*/
	if ((extend_heap(CHUNKSIZE / WSIZE)) == NULL)
		// 생성된 empty heap을 free block으로 확장
		// WSIZE로 align 되어있지 않으면 에러
		return -1;

    return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
	size_t asize; /*Adjusted block size*/
	size_t extendsize; /*Amount to extend heap if no fit*/
	char *bp;

	/*Ignore spurious requests*/
	if (size == 0)
		return NULL;

	/*Adjust block size to include overhead and alignment reqs.*/
	if (size <= DSIZE)
		asize = 2*DSIZE;
	else
		asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE);

	/*Search the free list for a fit*/
	if ((bp = find_fit(asize)) != NULL) {
		place(bp, asize);
		return bp;
	}

	/*No fit found. Get more memory and place the block*/
	extendsize = MAX(asize, CHUNKSIZE);
	if ((bp = extend_heap(extendsize/WSIZE)) == NULL)
		return NULL;
	place(bp, asize);
	return bp;
}

/*
 * free
 */
void free (void *ptr) {
    if(ptr == 0)
		return; // 잘못된 free 요청이면  함수를 종료. 이전 프로시져로 return
	size_t size = GET_SIZE(HDRP(ptr)); // ptr의 헤더에서 block size를 읽어옴
	
	/*실제로 데이터를 지우는 것이 아니라 
	  header와 footer의 최하위 1 bit(1, 할당된 상태)만을 수정*/

	PUT(HDRP(ptr), PACK(size, 0)); // ptr의 header에 block size와 alloc = 0 저장
	PUT(FTRP(ptr), PACK(size, 0)); // ptr의 footer에 block size와 alloc = 0 저장
	
	coalesce(ptr); // 주위에 빈 블록이 있을 시 병합
}

static void *extend_heap(size_t words){
	char *bp;
	size_t size;

	/* Allocate an even number of words to maintain alignment */
	size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
	if ((long)(bp = mem_sbrk(size)) == -1)
		return NULL;

	/* Initialize free block header/footer and the epilogue header*/
	PUT(HDRP(bp), PACK(size, 0)); /* Free block header */
	PUT(FTRP(bp), PACK(size, 0)); /* Free flock footer */
	PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); /* New epilogue header*/
	/* Coalesce if the previous block was free*/
	return coalesce(bp);
}

static void *coalesce (void *ptr) {
	size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(ptr)));
	// 이전 블럭의 할당 여부 0 = No, 1 = Yes
	size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
	// 다읍 블럭의 할당 여부 0 = No, 1 = Yes
	size_t size = GET_SIZE(HDRP(ptr));
	// 현재 블럭의 크기

	/*
	 * case 1 : 이전 블럭, 다음 블럭 최하위 bit가 둘다 1인 경우 (할당)
	 * 			블럭 병합 없이 ptr return
	 */
	if (prev_alloc && next_alloc) {
		return ptr;
	}

	/* case 2 : 이전 블럭 최하위 bit가 1이고 (할당),
	 * 			다음 블럭 최하위 bit가 0인 경우 (비할당)
	 *			다음 블럭과 병합한 뒤 ptr return
	 */
	else if (prev_alloc && !next_alloc) {
		size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
		PUT(HDRP(ptr), PACK(size, 0));
		PUT(FTRP(ptr), PACK(size, 0));
	}

	/* case 3 : 이전 블럭 최하위 bit가 0이고 (비할당),
	 *			다음 블럭 최하위 bit가 1인 경우 (할당)
	 *			이전 블럭과 병합한 뒤 새로운 ptr return
	 */

	else if (!prev_alloc && next_alloc) {
		size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
		PUT(FTRP(ptr), PACK(size, 0));	
		PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
		ptr = PREV_BLKP(ptr);
	}

	/* case 4 : 이전 블럭 최하위 bit가 0이고 (비할당),
	 *			다음 블럭 최하위 bit가 0인 경우 (비할당)
	 *			이전/ 현재/ 다음 블럭을 모두 병합한 뒤 새로운 ptr return
	 */
	else {
		size += GET_SIZE(HDRP(PREV_BLKP(ptr)))
			+ GET_SIZE(FTRP(NEXT_BLKP(ptr)));
		PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 0));
		ptr = PREV_BLKP(ptr);
	}

	return ptr;
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	size_t oldsize;
	void *newptr;

	if(size == 0) {
		free(oldptr);
		return 0;
	} // if size == 0, then this is just free and we return NULL.

	if(oldptr == NULL) {
		return malloc(size);
	} // if oldptr is NULL, then this is just malloc.

	newptr = malloc(size);

	// if realloc() fails the original block is left untouched.
	if(!newptr)
		return 0;

	// Copy the old data.
	oldsize = *SIZE_PTR(oldptr);
	if(size < oldsize)
		oldsize = size;
	memcpy(newptr, oldptr, oldsize);

	// Free the old block.
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

static void place(void *bp, size_t asize){
	size_t csize = GET_SIZE(HDRP(bp));

	if ((csize - asize) >= (2*DSIZE)){
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
static void *find_fit(size_t asize){
	/* First-fit search */
	void *bp;
	
	for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)){
		if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))){
			return bp;
		}
	}
	return NULL; /* No fit */
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
	char *bp = heap_listp;

}

