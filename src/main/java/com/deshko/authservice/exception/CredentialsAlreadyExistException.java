package com.deshko.authservice.exception;

public class CredentialsAlreadyExistException extends RuntimeException {
    public CredentialsAlreadyExistException(String message) {
        super(message);
    }
}
