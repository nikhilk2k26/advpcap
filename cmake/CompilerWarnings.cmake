# Compiler warnings configuration
function(set_target_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX-)
    else()
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            -Wnon-virtual-dtor
            -Wold-style-cast
            -Wcast-align
            -Wunused
            -Woverloaded-virtual
            -Wconversion
            -Wsign-conversion
            -Wnull-dereference
            -Wdouble-promotion
            -Wformat=2
        )
        
        if(ENABLE_SANITIZERS)
            target_compile_options(${target} PRIVATE
                -fsanitize=address
                -fsanitize=undefined
                -fno-omit-frame-pointer
            )
            target_link_options(${target} PRIVATE
                -fsanitize=address
                -fsanitize=undefined
            )
        endif()
    endif()
endfunction()
