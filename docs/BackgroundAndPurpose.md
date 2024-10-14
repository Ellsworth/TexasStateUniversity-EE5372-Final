# Intro for the paper

* With the emergence of IoT, IIoT, Embedded Systems, and many other things that require protecting data when communicating between devices, there is a strong need for encryption algorithms that would not be hungry for computational power. 

* ASCON - a lightweight cryptographic algorithm that's used for authenticated encryption and hashing. 

Developed in 2014 by a team of researchers from Graz University of Technology, Infineon Technologies, Lamarr Security Research, and Radboud University. Design is based on a sponge construction along the lines of SpongeWrap and MonkeyDuplex. 

Cool thing: even a small change in the message will result in a completely different hash, due to the avalanche effect

    * Pros:
        * Leightweight, secure, versatile, scalable, fast, NIST standard.
    * Cons: 
        * Not intended for post-quantum encryption. 

# Why?

* The purpose of this paper is to identify the weaknesses of the ASCON and suggest the optimal use case for different scenarious. The paper will cover 3 experiments that were evaluated on the effectiveness and security level.


