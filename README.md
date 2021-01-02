# Lattice ABS

This project is a Proof of Concept (PoC), about an Attribute-Based Signature scheme using lattices.

This PoC is theoretically based on the proposal of 
```
Jia, X., Yupu, H., Juntao, G., Wen, G., Xuelian, L., 2016. Attribute-based signatures on lattices. The Journal of China Universities of Posts and Telecommunications 23, 83–90. https://doi.org/10.1016/S1005-8885(16)60049-3
``` 

for the main proposal, and 

```
Gentry, C., Peikert, C., Vaikuntanathan, V., 2008. Trapdoors for hard lattices and new cryptographic constructions, in: Proceedings of the Fourtieth Annual ACM Symposium on Theory of Computing - STOC 08. Presented at the the 40th annual ACM symposium, ACM Press, Victoria, British Columbia, Canada, p. 197. https://doi.org/10.1145/1374376.1374407
```

for the base lattice trapdoor framework.

# Building the project

## Dependencies

This PoC was build using the PALISADE lattice library https://gitlab.com/palisade/palisade-release/-/wikis/home. More specifically, the framework of the GPV signature scheme implemented on this library was used as a base for this project.

## How to start building and testing the project

Start by getting the latest version of the PALISADE library [here](https://gitlab.com/palisade/palisade-release/-/tree/master) and it's dependencies. All the instructions should be on their wiki.

After getting the PALISADE installed, you can clone this repository:

```
$ git clone https://gitlab.unicamp.br/178499/lattice-abs-poc.git <path/of/your/choice>
```

Inside the newly cloned repository, create a directory to store the build files with:

```
$ mkdir build
$ cd build
```

and generate the Makefile using the cmake:

```
$ cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS=1
```

(Note: The flag is only to generate `compile_commands.json` if you want LSPs to understand the project structure) 

Then you can finally compile and run the example project:

``` 
$ make
$ lattice-abs
```
