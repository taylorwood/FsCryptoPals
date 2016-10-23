#load "Util.fs"

open System
open Util

// Challenge 9

let pad bytes length =
    let pad = Seq.initInfinite (fun _ -> 4uy)
    Seq.append bytes pad |> Seq.truncate length
let unpadded = "YELLOW SUBMARINE" |> stringToBytes
let padded = pad unpadded 20

// Challenge 10

open System.Security.Cryptography
let cryptAlg key =
    let aes = new AesManaged()
    aes.Mode <- CipherMode.ECB
    aes.Key <- key
    aes

let blockSize = 16

let encrypt (bytes: byte[]) key =
    use aes = cryptAlg key
    let encryptor = aes.CreateEncryptor(aes.Key, aes.IV)
    [| for block in bytes |> Array.chunkBySize blockSize do
        let padded = pad block blockSize |> Array.ofSeq
        let output = Array.create padded.Length 0uy
        encryptor.TransformBlock(padded, 0, padded.Length, output, 0) |> ignore
        yield! output |]
encrypt (stringToBytes "YELLOW SUBMARINE") (stringToBytes "YELLOW SUBMARINE")
let encryptCBCIV (iv: byte[]) (bytes: byte[]) key =
    let mutable prevBlock = iv
    [| for block in bytes |> Array.chunkBySize blockSize do
        let padded = pad block blockSize |> Array.ofSeq
        let xorBytes = xorBytes padded prevBlock |> Array.ofSeq
        let blockCipher = encrypt xorBytes key
        prevBlock <- blockCipher
        yield! blockCipher |]
let encryptCBC = encryptCBCIV (Array.create blockSize 0uy)
let bytes = stringToBytes "YELLOW TUBMARINE HEY HEY HEY HEY"
// encrypt bytes "YELLOW SUBMARINE"
let cipher = encryptCBC bytes (stringToBytes "ORANGE SUBMARINE")

let decrypt (aesBytes: byte[]) key =
    use aes = cryptAlg key
    let decryptor = aes.CreateDecryptor(aes.Key, aes.IV)
    let output = Array.create aesBytes.Length 0uy
    decryptor.TransformBlock(aesBytes, 0, aesBytes.Length, output, 0) |> ignore
    output
decrypt (cipher |> Array.take blockSize) (stringToBytes "ORANGE SUBMARINE") |> bytesToString
let decryptCBC (bytes: byte[]) key =
    let mutable prevBlock : byte[] = Array.create blockSize 0uy
    [| for block in bytes |> Array.chunkBySize blockSize do
        let padded = pad block blockSize |> Array.ofSeq
        let blockCipher = decrypt padded key
        let xorBytes = xorBytes blockCipher prevBlock |> Array.ofSeq
        prevBlock <- padded
        yield! xorBytes |]
decryptCBC cipher (stringToBytes "ORANGE SUBMARINE") |> bytesToString

let cbcBytes = readBase64Bytes (__SOURCE_DIRECTORY__ + "/Challenge10.txt")
decryptCBC cbcBytes (stringToBytes "YELLOW SUBMARINE") |> bytesToString |> printfn "%s"

// Challenge 11
let rnd = Random()
let coinflip () = rnd.NextDouble() < 0.5
let genAesKey () =
    let bytes = Array.create 16 0uy
    rnd.NextBytes bytes
    bytes
let crazyCrypt bytes =
    let leftPad = Array.create (rnd.Next(5,10)) 0uy
    let rightPad = Array.create (rnd.Next(5,10)) 0uy
    let bytes = Array.concat [| leftPad; bytes; rightPad |]
    let rndKey = genAesKey ()
    if coinflip ()
    then
        printfn "ECB"
        encrypt bytes rndKey
    else
        printfn "CBC"
        let iv = Array.create blockSize 0uy
        rnd.NextBytes iv
        encryptCBCIV iv bytes rndKey
let isECB crypt =
    let bytes = crypt (Array.create (blockSize * 6) 0uy) // use zeroed buffers to expose ECB repetition
    let blocks = bytes |> Array.chunkBySize blockSize
    blocks.Length > (blocks |> Array.distinct |> Array.length) // if there were duplicate blocks, ECB was used
isECB crazyCrypt

module ECBOracle =
    let append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK" |> Convert.FromBase64String

    let rndKey = genAesKey ()
    let crazyEcbCrypt bytes =
        encrypt bytes rndKey
let growingKeys = [for i in 1 .. 10 do yield String.replicate i "A"] |> List.map stringToBytes
let lenDiffs = // look for ciphertext size diffs given diff inputs
    growingKeys
    |> List.map (ECBOracle.crazyEcbCrypt >> Array.length)
    |> List.pairwise
    |> List.map (fun (x,y) -> abs(x-y))
    |> List.where (fun x -> x > 0)
    |> List.distinct
isECB ECBOracle.crazyEcbCrypt
let shorty = Array.create (blockSize-1) 0uy
let shortyCrypt = ECBOracle.crazyEcbCrypt shorty
let cryptBlam = [
    for b in Byte.MinValue .. Byte.MaxValue do
        let crypted = ECBOracle.crazyEcbCrypt (Array.append shorty [|b|])
        yield b, crypted ]

cryptBlam |> List.where (fun (b,c) -> c.[0..15] = shortyCrypt.[0..15])
