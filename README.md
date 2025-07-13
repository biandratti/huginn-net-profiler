# Huginn Net Profiler

[![CI](https://github.com/biandratti/huginn-net-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/biandratti/huginn-net-profiler/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org/)

## Introduction

This project was built to provide an easy-to-use, web-based interface for testing and profiling TCP, HTTP and TLS connections using the [huginn-net](https://github.com/biandratti/huginn-net) library. The motivation behind this project is to enable researchers, network engineers, and enthusiasts to analyze  connection characteristics in real time, without the need for complex command-line tools or manual packet analysis.

By exposing the huginn-net library through a simple web application, users can:
- Instantly view detailed TCP, HTTP and TLS connection profiles for their own or specified IP addresses.
- Experiment with different network scenarios and observe how signatures and metadata change.
- Use the tool for demonstrations, or diagnostics in real-world environments.

This project aims to make advanced profiling accessible and interactive, helping users better understand network behaviors and improve their own tools or research.

## Architecture
```
huginn-net-profiler/
├── huginn-core/          # Core analysis engine
├── huginn-collector/     # Network traffic collection
├── huginn-api/           # Web API server
└── static/               # Web UI assets
```

## Modules

### huginn-core
Core library for traffic analysis and fingerprinting.
- Clean data structures for TCP, HTTP, and TLS analysis
- Event system for real-time notifications
- Configurable analyzer with quality thresholds
- Error handling with thiserror integration

### huginn-collector
Network traffic collector that bridges huginn-net with huginn-core.
- Real-time network traffic collection
- Async/sync channel bridging
- Profile caching and merging
- Graceful shutdown handling
```
huginn-net (blocking) → ChannelBridge (thread) → ProfileProcessor (async) → huginn-core
```

### huginn-api
Web API server with REST endpoints and WebSocket support.
- Complete REST API for profile management
- Real-time WebSocket updates
- CORS support for web applications
- Static file serving
- Integrated network collection

## System Requirements

- Rust 1.80 or higher
- libpcap development libraries (use your system's package manager)
- Network interface access (requires root/sudo privileges)

## Quick Start

### 1. Build All Modules
```bash
cargo build --workspace --release
```

### 2. Run Web Application
```bash
# Find your network interface (e.g., ip link show, ifconfig)
ip link show

# Run the API server with your interface (defaults to port 3000)
# Use sudo if required for network capture
sudo ./target/release/huginn-api --interface eth0

# To run on a different port (e.g., 8080)
# sudo ./target/release/huginn-api --interface eth0 --bind 0.0.0.0:8080
```

### 3. Access the Web Interface
- Open your browser and go to `http://localhost:3000` (or your custom port)
- The web interface will show real-time network traffic analysis
- Replace `eth0` with your network interface name.

## Data Flow

```
Network Traffic
    ↓
huginn-net (TCP, HTTP. TLS packages process)
    ↓
huginn-collector (collection & processing)
    ↓
huginn-core (analysis & events)
    ↓
huginn-api (REST API & WebSocket)
    ↓
Web Client / External Applications
```