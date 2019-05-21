# SDCap
SDCap is an easy to use packet sniffer for SD Gundam Online.

# How did SDCap begin?
A friend of mine mentioned an old MMO game that he loved to play in his early childhood and I discovered there was a subreddit dedicated to
the now defunct game with many equally enthusiastic fans. Soon after, I realized there was a community behind an emulation of the game. I figured I'd try to see if I could discover anything about the game. As a result, I began looking into the game data, and trying to discover how the packets for the game work. Originally, I worked with Wireshark but realized it was too limited since it was a generic packet sniffer.

# Why SDCap over a generic packet sniffer such as Wireshark?
SDCap is designed specifically for SD Gundam Online and therefore, identifies information only particular to SD Gundam Online. See the features below for more information.

# Current Features
- Displaying of packet information only relevant to SD Gundam Online (this means there is no Ethernet header, IPv4 header, or TCP header)
- Naming of opcodes which are saved for every sniffing session to make identification of packets easier
- Loading of opcode definitions so that every sniffing session will contain your previously named opcodes

# Features Coming Soon
- Saving of sniffing sessions for further packet analysis
- Reloading of sniffing sessions for packet analysis
- Listing of opcodes and a way to navigate to find a particular opcode within the packet log

# How to use
## Dependencies
SDCap uses pcap4j 1.7.7 and as such has the same requirements. It also uses gson. To emphasize the most important requirements here, you will need a version of Java between Java 6.0 to Java 8.0. Java 9.0+ is not supported by pcap4j 1.7.7. In the future, SDCap will likely be updated once pcap4j 2.0 has reached its stable release.
Aside from this, you will need a pcap library. You may use WinPcap or Npcap on Windows, and libpcap if you are on *nix based system (ie. Linux or Mac OS). Other than that, the dependencies of pcap4j, and gson are all included in the pom.xml file. You will need Maven to compile this project. I will presume that you have prerequisite knowledge on Maven.

# License
See [LICENSE](https://github.com/brilam/SDCap/blob/master/LICENSE)

# Contributions
Bugs are inevitable in software, and as development goes further and further, we'll discover more about SD Gundam Online. Any contributions are welcome (bug fixes, enhancements, etc). Here are some steps to contributions:
1) Fork this repository.
2) Create a branch based on the master branch.
3) Write your code adhering to the Google Java style guide. Below are some nifty resources for those using Eclipse (you are not bound to Eclipse! You are more than welcome to use your favorite IDE):
   - [Checkstyle plugin](https://checkstyle.org/eclipse-cs/#!/) for checking if your code adheres to Google's style guide (which is checkstyle)
   - [Google's Style Formatter for Eclipse](https://github.com/google/styleguide/blob/gh-pages/eclipse-java-google-style.xml) for formatting your code to adhere to Google's style guide (which is checkstyle).
4) Send a pull request from your branch.
