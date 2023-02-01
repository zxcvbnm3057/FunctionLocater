FunctionLocater= FunctionLocater/LengthDisasm/LengthDisasm.o FunctionLocater/FunctionLocater.o
FunctionLocater_H= ./FunctionLocater/FunctionLocater.hpp ./FunctionLocater/LengthDisasm/LengthDisasm.h

FunctionLocater/FunctionLocater.o:  ./FunctionLocater/FunctionLocater.cpp ./FunctionLocater/FunctionLocater.hpp ./FunctionLocater/LengthDisasm/LengthDisasm.h
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

FunctionLocater/LengthDisasm/LengthDisasm.o: ./FunctionLocater/LengthDisasm/LengthDisasm.c ./FunctionLocater/LengthDisasm/LengthDisasm.h
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

FunctionLocater_clean:
	$(RM) ./FunctionLocater/*.o
	$(RM) ./FunctionLocater/LengthDisasm/*.o

.PHONY: FunctionLocater_clean