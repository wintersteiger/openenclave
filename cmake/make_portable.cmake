# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function(make_portable OE_TARGET)
    #Add dependency to compiler wrapper 
    add_dependencies(${OE_TARGET} clang_wrapper)
    
    # Setup library naming to match linux
    set(CMAKE_STATIC_LIBRARY_PREFIX "lib" PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX ".a" PARENT_SCOPE)

    # Setup library tool 
    set(CMAKE_C_CREATE_STATIC_LIBRARY "llvm-ar qc <TARGET> <OBJECTS>" PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY "llvm-ar qc <TARGET> <OBJECTS>" PARENT_SCOPE)

    # Setup linker for building enclaves.
	find_program(LD_LLD "ld.lld.exe")
	set(CMAKE_EXECUTABLE_SUFFIX "" PARENT_SCOPE)
	set(CMAKE_C_STANDARD_LIBRARIES "" PARENT_SCOPE)
	set(CMAKE_C_LINK_EXECUTABLE
    	"clang -target x86_64-pc-linux <OBJECTS> -o <TARGET>  <LINK_LIBRARIES> -fuse-ld=\"${LD_LLD}\""
        PARENT_SCOPE)
	set(CMAKE_CXX_STANDARD_LIBRARIES "" PARENT_SCOPE)		
	set(CMAKE_CXX_LINK_EXECUTABLE
    	"clang -target x86_64-pc-linux <OBJECTS> -o <TARGET>  <LINK_LIBRARIES> -fuse-ld=\"${LD_LLD}\""
        PARENT_SCOPE)    

    # Setup compilers
    set(CMAKE_C_COMPILE_OBJECT
		"\"${CMAKE_BINARY_DIR}/build_tools/clang_wrapper.exe\" -target x86_64-pc-linux <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>"
        PARENT_SCOPE)
	
	set(CMAKE_CXX_COMPILE_OBJECT
		"\"${CMAKE_BINARY_DIR}/build_tools/clang_wrapper.exe\" -target x86_64-pc-linux <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>"
        PARENT_SCOPE)
endfunction(make_portable)
