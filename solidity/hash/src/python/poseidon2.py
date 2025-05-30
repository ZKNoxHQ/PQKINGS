import ctypes
import os
import platform

def load_poseidon_lib():
    """Detects OS and loads the correct Poseidon2 shared library."""
    system = platform.system()

    if system == "Darwin":
        lib_name = "../build/libposeidon2_wrapper.dylib"  # macOS
    elif system == "Linux":
        lib_name = "../build/libposeidon2_wrapper.so"     # Linux
    elif system == "Windows":
        lib_name = "../build/poseidon2_wrapper.dll"       # Windows
    else:
        raise OSError(f"Unsupported OS: {system}")

    # Get absolute path to the library
    lib_path = os.path.abspath(lib_name)

    # Load the dynamic library
    try:
        poseidon_lib = ctypes.CDLL(lib_path)
    except OSError as e:
        raise RuntimeError(f"Failed to load {lib_name}: {e}")

    return poseidon_lib

def poseidon2_permute(input_array):
    """Calls the C function poseidon2_permute_babybear24 on a 24-element array."""
    if len(input_array) != 24:
        raise ValueError("Input array must have exactly 24 elements.")

    # Load the library
    poseidon_lib = load_poseidon_lib()

    # Define function signature
    poseidon_func = poseidon_lib.poseidon2_permute_babybear24
    poseidon_func.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    poseidon_func.restype = None  # Function returns void

    # Convert Python list to ctypes array
    input_ctypes = (ctypes.c_uint32 * 24)(*input_array)

    # Allocate output buffer
    output_ctypes = (ctypes.c_uint32 * 24)()

    # Call the function
    poseidon_func(input_ctypes, output_ctypes)

    # Convert output to Python list
    return list(output_ctypes)

# ==== Example Usage ====
if __name__ == "__main__":
    # Example input: Array of 24 uint32 values
    input_data = [i for i in range(24)]  # Example: [0, 1, 2, ..., 23]

    # Call Poseidon2 permutation
    output_data = poseidon2_permute(input_data)

    # Print results
    print("Input Data: ", input_data)
    print("Output Data:", output_data)
