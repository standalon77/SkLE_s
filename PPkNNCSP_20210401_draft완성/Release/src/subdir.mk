################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/ClientSocket.cpp \
../src/PPkNNCSPMain.cpp \
../src/PaillierCrypto.cpp \
../src/Socket.cpp 

OBJS += \
./src/ClientSocket.o \
./src/PPkNNCSPMain.o \
./src/PaillierCrypto.o \
./src/Socket.o 

CPP_DEPS += \
./src/ClientSocket.d \
./src/PPkNNCSPMain.d \
./src/PaillierCrypto.d \
./src/Socket.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


