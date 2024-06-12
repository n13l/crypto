# Intrusive Crypto Library
Crypto library is designed to maximize performance and efficiency through several key features

## Minimal Overhead Interface 
Avoids buffer copies and dynamic allocations to maintain high speed and resource efficiency. While dynamic allocation supports handling integers of any size, it may affect performance and introduce potential side-channel vulnerabilities.

## Hardware Acceleration with Software Fallback
Leverages hardware acceleration for enhanced performance, with efficient software fallback mechanisms to ensure reliability across different platforms.

## Cryptographic Hooks
Implements cryptographic and entropy level hooks based on different types of signatures that are independent of specific implementations and act as a crypto operation state machine. This flexibility supports robust testing and prototyping of attack vectors, enhancing the robustness of security measures.
