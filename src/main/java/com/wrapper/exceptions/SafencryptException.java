package com.wrapper.exceptions;

public class SafencryptException extends Exception {

    private static final long serialVersionUID = 894798122053539237L;


    public SafencryptException() {
        super();
    }

    SafencryptException(final String message, Exception ex) {
        super(message, ex);
    }


    public SafencryptException(String msg) {
        super(msg);
    }


    public SafencryptException(String message, Throwable cause) {
        super(message, cause);
    }


    public SafencryptException(Throwable cause) {
        super(cause);
    }
}
