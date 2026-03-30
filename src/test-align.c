void test_align() {
  // align_d
  static_assert(align_d(15, 8) == 8, "align_d(15, 8) should be 8");
  static_assert(align_d(16, 8) == 16, "align_d(16, 8) should be 16");

  // test common types: int->4, double->8
  static_assert(align_d(15, int) == 12, "align_d(15, int) should be 12");
  static_assert(align_d(15, double) == 8, "align_d(15, double) should be 8");

  // default alignas(8)
  static_assert(align_d(15) == 8, "align_d(15) default alignment should fallback to 8");

  // align_u_dist
  static_assert(align_u_dist(15, 8) == 1, "Distance from 15 to 16 is 1");
  static_assert(align_u_dist(16, 8) == 0, "Distance from 16 to 16 is 0");
  static_assert(align_u_dist(17, 8) == 7, "Distance from 17 to 24 is 7");
  static_assert(align_u_dist(1, 8) == 7);

  // test common types: int->4, double->8
  static_assert(align_u_dist(13, int) == 3, "Distance from 13 up to 16 (4-byte align) is 3");
  static_assert(align_u_dist(9, double) == 7, "Distance from 9 up to 16 (8-byte align) is 7");

  // overflow boundary
  static_assert(align_u_invalid(4096) == 0xFFFFFFFFFFFFF000ULL, "Page overflow boundary check");
  static_assert(align_u_invalid(8) == 0xFFFFFFFFFFFFFFF8ULL, "8-byte overflow boundary check");

  // for struct
  typedef struct {
    alignas(16) char data[16];
  } Vec128;
  static_assert(align_u_invalid(Vec128) == 0xFFFFFFFFFFFFFFF0ULL, "Type-based overflow boundary check");

  // array should downgrade to pointer
  char test_arr[10];
  static_assert(align_d(test_arr) == (uintptr_t)test_arr);
}
