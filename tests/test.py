import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from key_tree import KeyTree

def main():
    kt = KeyTree()
    kt.generateTree("hej")
    kt.printtest()
    print(kt.createProof(2))
main()