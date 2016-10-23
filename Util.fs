module Util

open System

let hexToByte = function
    | '0' -> 0uy | '1' -> 1uy | '2' -> 2uy | '3' -> 3uy | '4' -> 4uy | '5' -> 5uy | '6' -> 6uy | '7' -> 7uy | '8' -> 8uy | '9' -> 9uy
    | 'a' -> 10uy | 'b' -> 11uy | 'c' -> 12uy | 'd' -> 13uy | 'e' -> 14uy | 'f' -> 15uy
    | _ -> failwith "Invalid hexadecimal character"

let hexToBytes (hexChars: string) : byte array =
    [| for i in 0 .. 2 .. hexChars.Length - 1 do
        let hi = hexToByte hexChars.[i]
        let lo = hexToByte hexChars.[i+1]
        yield (hi <<< 4) ||| lo |]

let xorBytes (b1: #seq<byte>) (b2: #seq<byte>) =
    Seq.zip b1 b2 |> Seq.map (fun (x,y) -> x ^^^ y)

let printBytesHex (bytes: byte seq) = bytes |> Seq.map (sprintf "%02x") |> String.concat "" |> printfn "%s"

let xorBytesWith (bytes: byte[]) value = bytes |> Array.map (fun b -> b ^^^ value)

let stringToBytes (s: string) = Text.Encoding.ASCII.GetBytes s
let bytesToString (b: byte[]) = Text.Encoding.ASCII.GetString b

let bitDist (x: byte, y: byte) =
    let countBits b =
        let mutable set = 0
        for i in 0 .. 7 do
            let isSet = (b >>> i) &&& 1uy = 1uy
            if isSet then set <- set + 1
        set
    countBits (x ^^^ y)

/// Gets the cartesian product of a list of lists.
let rec cartesian lstlst =
    match lstlst with
    | h::[] ->
        List.fold (fun acc elem -> [elem]::acc) [] h
    | h::t ->
        List.fold (fun cacc celem ->
            (List.fold (fun acc elem -> (elem::celem)::acc) [] h) @ cacc) [] (cartesian t)
    | _ -> []

let readBase64Bytes filePath = IO.File.ReadAllLines(filePath) |> String.concat "" |> Convert.FromBase64String