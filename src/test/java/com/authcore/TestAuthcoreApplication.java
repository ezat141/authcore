package com.authcore;

import org.springframework.boot.SpringApplication;

public class TestAuthcoreApplication {

	public static void main(String[] args) {
		SpringApplication.from(AuthcoreApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
