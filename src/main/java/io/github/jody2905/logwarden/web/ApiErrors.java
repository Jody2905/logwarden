package io.github.jody2905.logwarden.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.Map;
import java.util.NoSuchElementException;

/** Errors as {"error": "..."} with a sensible status, never a stack trace. */
@RestControllerAdvice
public class ApiErrors {

    @ExceptionHandler({IllegalArgumentException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<Map<String, String>> bad(Exception e) {
        String msg = e instanceof MethodArgumentTypeMismatchException m ? "Bad value for " + m.getName() : e.getMessage();
        return ResponseEntity.badRequest().body(Map.of("error", msg == null ? "Bad request" : msg));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<Map<String, String>> invalid(MethodArgumentNotValidException e) {
        var f = e.getBindingResult().getFieldError();
        return ResponseEntity.badRequest().body(Map.of("error", f == null ? "Invalid request" : f.getField() + " " + f.getDefaultMessage()));
    }

    @ExceptionHandler(NoSuchElementException.class)
    ResponseEntity<Map<String, String>> missing(NoSuchElementException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage() == null ? "Not found" : e.getMessage()));
    }
}
