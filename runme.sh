#!/bin/bash
# https://www.bouncycastle.org/download/bctls-jdk15on-160.jar
# https://www.bouncycastle.org/download/bcprov-ext-jdk15on-160.jar
javac -cp bcprov-ext-jdk15on-160.jar:bctls-jdk15on-160.jar:. TlsExample1.java
