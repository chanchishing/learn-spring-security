package com.in28mintues.learnspringsecurity.resources;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class TodoResource {


    private Logger logger= LoggerFactory.getLogger(getClass());
    public static final List<Todo> TODOS =
            List.of(new Todo("in28minutes", "Learn AWS"),
                    new Todo("in28minutes", "Get AWS Certified"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllToDos(){
        return TODOS;
    }

    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username==authentication.name")
    @PostMapping("returnObject.username=='in28minutes'")
    @RolesAllowed({"USER","ADMIN"})
    @Secured({"ROLE_USER","ROLE_ADMIN"})
    public List<Todo> getTodosForAUser(@PathVariable String username){
        return TODOS.stream().filter(todo->todo.username().equals(username)).collect(Collectors.toList());
    }

    @PostMapping("/users/{username}/todos")
    public void createTodoForAUser(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Create {} for {}",todo,username);
        return;
    }

}

record Todo (String username,String description) {};
