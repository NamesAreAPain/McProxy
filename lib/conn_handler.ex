defmodule Mcproxy.ConnHandler do
  use GenStateMachine, callback_mode: [:handle_event_function, :state_enter]
  alias __MODULE__
  import Mcproxy

  
  @keypair (fn -> 
    {:RSAPrivateKey,_,mod,pubexp,_,_,_,_,_,_,_} = priv = :public_key.generate_key({:rsa,1024,65537})
    pub = {:RSAPublicKey,mod,pubexp}
    {priv,pub}
  end).()

  def keys(), do: @keypair

  def start_server(port \\ 25565) do
    {:ok, socket} = :gen_tcp.listen(port,[:list, packet: 0, active: true, reuseaddr: true])
    IO.puts("Listening on port #{port}")
    server_loop(socket)
  end

  def server_loop(socket) do
    :ok = case :gen_tcp.accept(socket) do
      {:ok, client} ->
        {:ok,statem} = ConnHandler.start(client)
        :gen_tcp.controlling_process(client,statem)
        :ok
      {:error, :closed} -> "TCP port closed"
      _ -> :ok
    end
    server_loop(socket)
  end

  def start(client) do
    GenStateMachine.start(ConnHandler,{:init,client})
  end

  def init({initial_state,data}) do
    {:ok,initial_state,data}
  end

  def handle_event(:enter,_event,:init,_client) do
    IO.inspect "Waiting For Connections"
    :keep_state_and_data
  end

  def handle_event(:cast,%{id: 0x00,rest: rest} = packet,:init, client) do
    %{protocol_version: _version,
      address: _addr,
      port: _port,
      next_state: next
    } = parse_packet(
      rest,
      [
        protocol_version: :varint,
        address: :string,
        port: :ushort,
        next_state: :varint
      ],
      packet
    ) |> IO.inspect()
    case next do
      1 -> {:next_state, :status, client}
      2 -> {:next_state, :login, client}
    end
  end

  def handle_event(:enter,_event,:status,client) do
    IO.inspect "Received Status Check"
    res = create_reply([
      byte: 0x00, 
      string: ~s(
      {
        "version": {
          "name": "1.8.4",
          "protocol": 47    
        },
        "players": {
          "max": 6,
          "online": 0,
          "sample": []
        },
        "description": {
          "text": "ALLLIIIIVVVEEE"
        }
      }
      )
    ])
    :gen_tcp.send(client,res)
    IO.inspect "Sent Status Response"
    :keep_state_and_data
  end

  def handle_event(:cast,%{id: 0x01, rest: rest}=packet,:status,client) do
    IO.inspect "Received Ping"
    %{ping: ping} = parse_packet(rest,[ping: :ulong],packet)
    :gen_tcp.send(client,create_reply([byte: 0x01,ulong: ping]))
    IO.inspect "Sent Pong"
    :gen_tcp.shutdown(client,:read_write)
    {:stop,:normal}
  end

  def handle_event(:cast,%{id: 0x00, rest: rest} = packet, :login,client) do
    IO.inspect "Received Login Start"
    %{name: _name} = parse_packet(rest,[name: :string],packet)
    {:next_state,:encrypt,client}
  end

  def handle_event(:enter,_event,:encrypt,client) do
    {_priv,pub} = @keypair
    token = :crypto.strong_rand_bytes(4) 
            |> Base.url_encode64 
            |> binary_part(0, 4)
    res = create_reply([
      byte: 0x01,
      string: "",
      string: der_encode(:RSAPublicKey,pub),
      string: token
    ])
    IO.inspect( parse_packet(res,[id: :byte, server_id: :string, pubkey: :string, toke: :string] ))
    :gen_tcp.send(client,res)
    IO.inspect "Sent Encrpytion Key Request"
    :keep_state_and_data
  end

  def handle_event(:cast,%{id: 0x01, rest: rest}=packet,:encrypt,client) do
    %{
      shared_secret: _ss,
      verify_token: _token,
    } = parse_packet(
      rest,
      [
        shared_secret: :string, 
        verify_token: :string
      ],
      packet
    )
    IO.inspect "Recieved Encryption Response"
    {:next_state,:sucess,client}
  end

  def handle_event(:enter,_event,:success,client) do
    res = create_reply([
      byte: 0x00,
      string: ~s({"text":"Not a minecraft server"})
    ])
    :gen_tcp.send(client,res)
    IO.inspect "Sent Disconnect"
    {:stop,:normal}
  end

  def handle_event(:info, {:tcp, _from, contents}, _state, _client) do
    IO.inspect "tcp packet: #{inspect(contents)}"
    case contents do
      [0xFE|_] -> 
        GenStateMachine.cast(self(),:legacy_ping)
      _ -> 
        parse_packet(contents,[id: :byte,rest: :rest])
        |> (&GenStateMachine.cast(self(),&1)).()
    end
    :keep_state_and_data
  end

  def handle_event(:info, {:tcp_closed,_from},_state,_client) do
    IO.inspect "TCP Socket closed"
    {:stop,:normal}
  end

  def handle_event(:enter,_event,state,_data) do
    IO.inspect "Entering State: #{state}"
    :keep_state_and_data
  end

  def handle_event(event_type, event_content, state, data) do
    IO.inspect "#{event_type} #{inspect(event_content)}"
    super(event_type, event_content, state, data)
  end 
end
