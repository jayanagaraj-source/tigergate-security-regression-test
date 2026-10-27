package com.example.loc;

/**
 * Greeter used by the XML bean fixture.
 */
public class Greeter {
    // The greeting is injected from beans.xml.
    private String greeting = "hello";

    public void setGreeting(String greeting) {
        this.greeting = greeting;
    }

    public String greet(String name) {
        return greeting + ", " + name;
    }
}
