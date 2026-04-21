# NIZKP Forensics Suite

A privacy-preserving digital forensics prototype that allows a prover to demonstrate the existence of network artifacts from a PCAP file without exposing the original dataset.

## Overview

This project explores how non-interactive zero-knowledge style proof construction can be applied to digital forensics workflows. Instead of sharing raw packet captures, the system generates a proof bundle that allows a verifier to check whether a specific network connection exists while keeping the underlying evidence private.

## Features

- PCAP import and parsing with Scapy
- GUI-based Prover and Verifier interfaces
- Connection filtering and payload-aware analysis
- Encrypted Bloom filter proof construction
- Password-based key derivation using Argon2id
- AES-GCM authenticated encryption
- Ed25519 digital signatures for proof integrity
- Optional proof expiration support

## Project Structure

- `main.py` - main GUI launcher
- `prover.py` - prover interface and PCAP analysis workflow
- `verifier.py` - verifier interface for proof validation
- `zk_engine.py` - cryptographic proof generation and verification logic

## Research Motivation

Digital evidence often contains sensitive information that should not be broadly shared. This project investigates whether cryptographic proof systems can support forensic validation while reducing unnecessary disclosure of raw evidence.

## Example Workflow

1. Import a PCAP file in the Prover
2. Search and select a connection
3. Generate a password-protected proof
4. Share the proof JSON with a verifier
5. Enter the connection details in the Verifier
6. Verify the claim without revealing the original PCAP

## Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
