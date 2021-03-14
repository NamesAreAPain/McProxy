defmodule Mcproxy do
  use Bitwise
  
  # parse_packet(packet,[type: :byte,username: :string,... ])

  def parse_packet(data,segments) do
    parse_packet(data,[{:len, :varint} | segments],%{})
  end

  def parse_packet([],[],out) do
    out |> Map.delete(:rest)
  end

  def parse_packet(rest,[],out) do
    send(self(),{:tcp, :unused, rest})
    parse_packet([],[],out)
  end

  def parse_packet(data,[{key,:rest}],out) do
    Map.put(out,key,data)
  end

  def parse_packet([byte| tail],[{key,:byte}| segments],out) do
    parse_packet(tail,segments,Map.put(out,key,byte))
  end
  
  def parse_packet(data,[{key,:varint}| segments],out) do
    {varint,[a| rest]} = Enum.split_while(data,
      fn x -> (x &&& 0b10000000) != 0 end
    )
    :true = Enum.count(varint) < 10
    varint = Enum.reduce(Enum.reverse(varint++ [a]),0,fn x, acc -> acc*128 + (x &&& 0b01111111) end)
    parse_packet(rest,segments,Map.put(out,key,varint))
  end

  def parse_packet(data,[{key, :string}| segments],out) do
    %{len: strlen, rest: rest} = parse_packet(data,[len: :varint,rest: :rest],%{})
    {str,rest} = Enum.split(rest,strlen)
    str = List.to_string(str)
    parse_packet(rest,segments,Map.put(out,key,str))
  end

  def parse_packet(data,[{key, :ushort}| segments],out) do
    {[a,b], rest} = Enum.split(data,2)
    parse_packet(rest,segments,Map.put(out,key,(a*256)+b))
  end

  def parse_packet(data,[{key,:ulong}| segments],out) do
    {[a,b,c,d], rest} = Enum.split(data,4)
    parse_packet(rest,segments,Map.put(out,key,(a*16777216)+(b*65536)+(c*256)+d))
  end

  def create_reply(content) do
    out = Enum.flat_map(content,fn {type,x} -> create_reply(type,x) end)
    create_reply(:varint,Enum.count(out)) ++ out
  end
  def create_reply(:varint,int) do
    [msb|rest] = expand_while(int,fn x -> {Integer.mod(x,127),Integer.floor_div(x,127)} end, fn x -> x != 0 end)
    |> Enum.reverse()
    [msb &&& 0b01111111] ++ Enum.map(rest,fn x -> x ||| 0b10000000 end)
    |> Enum.reverse()
  end
  def create_reply(:string,str) do
    create_reply(:varint,byte_size(str)) ++ :binary.bin_to_list(str)
  end

  def create_reply(:ulong,x) do
    x |> :binary.encode_unsigned() |> :binary.bin_to_list()
  end

  def create_reply(:byte,x) do
    [x]
  end

  defp expand_while(acc,f,condition) do
    expand_while_r(acc,f,condition,[],true)
  end

  defp expand_while_r(_acc,_f,_condtion,list,false), do: list

  defp expand_while_r(acc,f,condition,list,true) do
    {val,acc} = f.(acc)
    cont = condition.(acc)
    expand_while_r(acc,f,condition,list ++ [val],cont)
  end

  def der_encode(:RSAPublicKey,pub) do
    der_encoded = :public_key.der_encode(:RSAPublicKey,pub)
    :public_key.pem_encode([{:RSAPublicKey,der_encoded,:not_encrypted}]) 
    |> IO.inspect()
  end
  def der_encode(:RSAPrivateKey,priv) do
    der_encoded = :public_key.der_encode(:RSAPrivateKey,priv)
    :public_key.pem_encode([{:RSAPrivateKey,der_encoded,:not_encrypted}]) 
    |> IO.inspect()
  end

  defp der_test_encode(:RSAPrivateKey,priv) do
    {_,data,_} = :public_key.pem_entry_encode(:RSAPrivateKey,priv)
    "-----BEGIN PUBLIC KEY-----"<>( data |> Base.encode64 )<>"-----END PUBLIC KEY-----"
  end
end
