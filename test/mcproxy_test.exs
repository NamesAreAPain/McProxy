defmodule McproxyTest do
  use ExUnit.Case
  doctest Mcproxy

  test "greets the world" do
    assert Mcproxy.hello() == :world
  end
end
