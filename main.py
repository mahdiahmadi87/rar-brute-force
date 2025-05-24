#!/usr/bin/env python3
"""
High-Performance RAR Password Recovery Script
Brute-forces numeric passwords (0-99999999) using multiprocessing
"""

import rarfile
import multiprocessing as mp
import itertools
import time
import sys
import os
from pathlib import Path


class PasswordFound(Exception):
    """Custom exception to signal password discovery"""
    def __init__(self, password):
        self.password = password
        super().__init__(f"Password found: {password}")


def test_password_chunk(args):
    """
    Test a chunk of passwords against the RAR file
    Returns the password if found, None otherwise
    """
    rar_path, start_num, end_num, chunk_id = args
    
    try:
        for num in range(start_num, end_num + 1):
            password = str(num).zfill(8)  # Pad with zeros for consistent length
            
            try:
                with rarfile.RarFile(rar_path) as rf:
                    rf.setpassword(password)
                    
                    # Get file list
                    file_list = rf.infolist()
                    if not file_list:
                        continue  # No files in archive
                    
                    # Try to actually read/extract the first file to verify password
                    first_file = file_list[0]
                    
                    # For small files, try to read completely
                    if first_file.file_size < 1024 * 1024:  # Less than 1MB
                        rf.read(first_file.filename)
                    else:
                        # For larger files, just read first few bytes
                        with rf.open(first_file.filename) as f:
                            f.read(1024)  # Read first 1KB
                    
                    return password  # Password is correct if we reach here!
                    
            except rarfile.RarWrongPassword:
                continue  # Wrong password, try next
            except rarfile.BadRarFile:
                continue  # Corrupted or invalid RAR
            except Exception as e:
                # Handle other potential errors (but continue trying)
                continue
                
        return None  # No password found in this chunk
        
    except Exception as e:
        print(f"Error in chunk {chunk_id}: {e}")
        return None


def create_password_chunks(max_password, num_processes):
    """
    Divide the password space into chunks for multiprocessing
    """
    chunk_size = max_password // num_processes
    chunks = []
    
    for i in range(num_processes):
        start = i * chunk_size
        end = start + chunk_size - 1
        
        # Make sure the last chunk covers any remaining passwords
        if i == num_processes - 1:
            end = max_password
            
        chunks.append((start, end, i))
    
    return chunks


def extract_rar_file(rar_path, password, extract_path=None):
    """
    Extract the RAR file using the found password
    """
    if extract_path is None:
        extract_path = Path(rar_path).parent / "extracted"
    
    try:
        os.makedirs(extract_path, exist_ok=True)
        
        with rarfile.RarFile(rar_path) as rf:
            rf.setpassword(password)
            
            # Verify password works before extraction
            file_list = rf.infolist()
            if file_list:
                # Test read first file to confirm password
                first_file = file_list[0]
                if first_file.file_size > 0:
                    with rf.open(first_file.filename) as f:
                        f.read(min(1024, first_file.file_size))
            
            # If we get here, password is verified - proceed with extraction
            rf.extractall(path=extract_path)
            
        print(f"✅ Successfully extracted to: {extract_path}")
        return True
        
    except rarfile.RarWrongPassword:
        print(f"❌ Password verification failed during extraction: {password}")
        return False
    except Exception as e:
        print(f"❌ Error extracting file: {e}")
        return False


def brute_force_rar_password(rar_path, max_digits=8, num_processes=None):
    """
    Main function to brute-force RAR password using multiprocessing
    """
    if not os.path.exists(rar_path):
        print(f"❌ RAR file not found: {rar_path}")
        return None
    
    if num_processes is None:
        num_processes = mp.cpu_count()
    
    max_password = 10 ** max_digits - 1  # 99999999 for 8 digits
    
    print(f"🔍 Starting password recovery for: {rar_path}")
    print(f"🔢 Testing passwords from 0 to {max_password:,}")
    print(f"🚀 Using {num_processes} CPU cores")
    print(f"⏱️  Starting brute-force attack...\n")
    
    start_time = time.time()
    
    # Create password chunks for each process
    chunks = create_password_chunks(max_password, num_processes)
    
    # Prepare arguments for each worker process
    worker_args = [(rar_path, start, end, chunk_id) for start, end, chunk_id in chunks]
    
    try:
        # Use multiprocessing pool to distribute work
        with mp.Pool(processes=num_processes) as pool:
            # Use imap for better control and early termination
            results = pool.imap(test_password_chunk, worker_args)
            
            for result in results:
                if result is not None:  # Password found!
                    pool.terminate()  # Stop all processes immediately
                    pool.join()
                    
                    elapsed_time = time.time() - start_time
                    
                    print(f"🎉 POTENTIAL PASSWORD FOUND: {result}")
                    print(f"⏱️  Time elapsed: {elapsed_time:.2f} seconds")
                    print(f"🔍 Verifying password and extracting...")
                    
                    # Extract the RAR file to verify password is truly correct
                    if extract_rar_file(rar_path, result):
                        print(f"✅ PASSWORD CONFIRMED: {result}")
                        return result
                    else:
                        print(f"❌ False positive - continuing search...")
                        # Continue with the brute force if extraction failed
                        break
                    
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        return None
    except Exception as e:
        print(f"❌ Error during brute-force: {e}")
        return None
    
    elapsed_time = time.time() - start_time
    print(f"❌ Password not found after testing {max_password:,} combinations")
    print(f"⏱️  Time elapsed: {elapsed_time:.2f} seconds")
    return None


def main():
    """
    Main entry point
    """
    if len(sys.argv) != 2:
        print("Usage: python rar_bruteforce.py <path_to_rar_file>")
        sys.exit(1)
    
    rar_file_path = sys.argv[1]
    
    # Check if rarfile library is available
    try:
        import rarfile
    except ImportError:
        print("❌ rarfile library not found. Install it with: pip install rarfile")
        print("   You may also need to install unrar tool on your system")
        sys.exit(1)
    
    # Set the path to unrar tool if needed (adjust for your system)
    # rarfile.UNRAR_TOOL = "unrar"  # or full path like "/usr/bin/unrar"
    
    password = brute_force_rar_password(rar_file_path, max_digits=8)
    
    if password:
        print(f"\n✅ Success! Password: {password}")
    else:
        print("\n❌ Password recovery failed")


if __name__ == "__main__":
    # Ensure multiprocessing works correctly on all platforms
    mp.freeze_support()
    main()