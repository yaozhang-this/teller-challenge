defmodule TellerTest do
  use ExUnit.Case
  doctest Teller

  test "greets the world" do
    assert Teller.hello() == :world
  end
end
