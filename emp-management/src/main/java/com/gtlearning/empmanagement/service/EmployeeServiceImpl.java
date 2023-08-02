package com.gtlearning.empmanagement.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.stereotype.Service;


import com.gtlearning.empmanagement.model.Employee;
import com.gtlearning.empmanagement.repository.EmployeeRepository;

@Service
public class EmployeeServiceImpl implements EmployeeService{

	@Autowired
	private EmployeeRepository employeeRepository;

	@Override
	public List<Employee> getAllEmployees() {
		
		return employeeRepository.findAll();
	}

	@Override
	public Employee saveEmployee(Employee employee) {
		return this.employeeRepository.save(employee);
		
	}

	@Override
	public Employee getEmployeeById(long id) {
		
		return employeeRepository.findById(id).orElseThrow();
	}

	@Override
	public void deleteEmployeeById(long id) {
		 this.employeeRepository.deleteById(id);
		
		
	}

	



	
	
	
}
