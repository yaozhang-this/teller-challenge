# Teller

This repo hosts the solution for the teller bank challenge.

 
## Installation

- Run `mix deps.get` to install required dependencies.
- open interactive terminal by `iex -S mix`


## Test
- on the command line, type in the driver code to have a walkthrough of the APIs created for Teller customers
```
{:ok, token} = Teller.Customer.get_token()
Teller.Customer.enroll("teller", "yellow_smokey", "gabon", token)
Teller.Customer.choose_mfa_method("SMS", token)
Teller.Customer.verify_mfa_with_code(123456, token) // returns account_id
Teller.Customer.get_account("acc_u2fed4l2ozezh6rxbmn52bogaey2xiac6pfzt3q", token)
```

By the end, you should see a list of user transactions as well as decrypted 12 digits account number of that user

## Documentation

The codebase consists of three modules: 
- Internal
- APIServer
- Customer

The internal module contains the client code used to communicate with the bank API directly.
APIServer module is a simple GenServer used to store and retrieve currently enrolled users.
Customer module uses the APIServer and return the query result to mini teller customers.

The above solves the challenge as required. More documentation can be found inside comments.

## Future Improvements
There are many things that could be improved in this codebase with more experience using Elixir, such as the use of GenServers, unit test, Elixir-way of functional programming, etc
I can also refactor some functions if I know more about the bank APIs we are using.



