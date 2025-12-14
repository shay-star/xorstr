 ### Introduction

This is a C++ header-only library that implements compile-time XOR encryption for string literals using C++17/20 features , alongside SIMD (AVX2/AVX) instructions for efficient runtime decryption.

This project was created as a personal C++ practice exercise to deepen my understanding of advanced modern C++ techniques, including:


### ✨ Features

- **Compile-Time Encryption:** All string literals are encrypted during the compilation process using `constexpr` functions.

- **Unique Keys per String:** A high-entropy seed combined with `__COUNTER__` and `__LINE__` ensures that each string literal uses a unique, context-dependent encryption key sequence.

- Very fast runtime decryption via AVX2

- **Header-only**, no external dependencies

- Works with `char` and `wchar_t`


### 🚀 Usage

1. **Include the Header:** Ensure your compiler supports C++17 or later and include header file.

2. **Use the Macro:** Wrap your string literals with the `XOR_STR` macro.


### quick example
```C++

void example()
{
    const std::string secret = XOR_STR("Secret Key: 0xDEADBEEF");
    std::cout << secret << std::endl;
    std::cout << XOR_STR("Application Initialized") << std::endl;
}

```

### Requirements

1. Compiler with **C++20** support

2. Compile with **AVX2** enabled
