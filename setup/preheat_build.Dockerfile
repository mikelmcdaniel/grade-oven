FROM grade_oven/grade_oven_base
# Note that there is no "clang-format" package, but "clang-3.4" happens to be
# the latest version of clang in the repo as of 2015-11-27.
RUN ["apt-get", "--assume-yes", "install", "binutils", "clang", "make", "clang-format-3.4"]
# TODO: make a usable .clang-format file
USER grade_oven
