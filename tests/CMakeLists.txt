if (NOT BUILD_TESTING)
    return()
endif()

    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.7.0
    )
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(Catch)

    add_executable(xorstr_tests test.cpp)

    target_link_libraries(xorstr_tests
        PRIVATE
            xorstr
            Catch2::Catch2WithMain
    )
    target_compile_features(xorstr_tests PRIVATE cxx_std_23)

    include(Catch)
    catch_discover_tests(xorstr_tests)





# 性能测试
# add_executable(pattern_scanner_bench bench.cpp catch_amalgamated.cpp)
# target_link_libraries(pattern_scanner_bench PRIVATE pattern_scanner)
# add_test(NAME PatternScanner.Benchmarks COMMAND pattern_scanner_bench)
# set_tests_properties(PatternScanner.Benchmarks PROPERTIES LABELS "Bench")
