#load "Util.fs"

open System
open Util

// Challenge 1: Convert hexadecimal string to base64
        
let bytes = hexToBytes "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
let base64 = Convert.ToBase64String bytes

// Challenge 2: XOR two hexadecimal strings

let hexBytesA = hexToBytes "1c0111001f010100061a024b53535009181c"
let hexBytesB = hexToBytes "686974207468652062756c6c277320657965"

printBytesHex (xorBytes hexBytesA hexBytesB)

// Challenge 3: Single-byte XOR cipher

let cryptBytes = hexToBytes "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

let isLikelyMatch (str: string) =
    let isPunctuation c = c = ',' || c = ''' || c = '.' || c = '?' || c = '!'
    let isTypical c = Char.IsLetter c || c = ' ' || isPunctuation c
    let letters = str |> Seq.where Char.IsLetter |> Seq.length
    let lowers = str |> Seq.where Char.IsLower |> Seq.length
    let ratio check =
        let n = str |> Seq.where check |> Seq.length
        float n / float str.Length
    (ratio isPunctuation) < 0.2 &&
    (ratio isTypical) > 0.9 &&
    (float letters / float str.Length) > 0.5 &&
    (float lowers / float letters) > 0.5
let brute' cryptBytes = seq {
    for b in 0uy .. 255uy do
        yield b, xorBytesWith cryptBytes b |> bytesToString }
let brute = brute' >> Seq.map snd
brute cryptBytes |> Seq.where isLikelyMatch |> Seq.iter (printfn "%s")

// Challenge 4: Find the XOR encrypted Text

let cryptStrings = IO.File.ReadAllLines(__SOURCE_DIRECTORY__ + "/Challenge4.txt")
let possibleDecrypts =
    cryptStrings
    |> Seq.map (hexToBytes >> brute)
    |> Seq.indexed
    |> Seq.map (fun (i,cs) -> i, cs |> Seq.where isLikelyMatch |> Array.ofSeq)
    |> Seq.where (fun (i,cs) -> cs.Length > 0)
possibleDecrypts |> Seq.iter (printfn "%A")

// Challenge 5: Implement repeating-key XOR

let stanza = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
let stanzaBytes = stringToBytes stanza
let key = "ICE".ToCharArray() |> Array.map byte
let repeatKey length (key: 'a array) = seq { for i in 0 .. length - 1 do yield key.[i % key.Length] }
let repetitiveKey = repeatKey stanzaBytes.Length key
let encryptedStanza = Seq.zip stanzaBytes repetitiveKey |> Seq.map (fun (x,y) -> x ^^^ y)
printBytesHex encryptedStanza

// Challenge 6

let b1 = stringToBytes "this is a test"
let b2 = stringToBytes "wokka wokka!!!"
let testDist = Seq.zip b1 b2 |> Seq.sumBy bitDist // should equal 37

let repeatKeyCryptBytes =
    IO.File.ReadAllLines(__SOURCE_DIRECTORY__ + "/Challenge6.txt")
    |> String.concat ""
    |> Convert.FromBase64String

let keySizes = [2 .. 40] // key sizes (lengths) to analyze

let getAverageBlockDists buffer keySize =
    buffer
    |> Seq.chunkBySize keySize
    |> Seq.chunkBySize 2
    |> Seq.truncate 6
    |> Seq.map (fun bp -> Array.zip bp.[0] bp.[1] |> Array.sumBy bitDist |> float)
    |> Seq.average
// calc the bit/hamming distance for each key size
let keySizeBlockDists = keySizes |> List.map (getAverageBlockDists repeatKeyCryptBytes)
let blockDistsNorm = // fst is key size, snd is normalized block distance
    List.zip keySizes keySizeBlockDists
    |> List.map (fun (ks,dist) -> ks, dist / float ks) // normalize distances by key size
    |> List.sortBy snd
let findLikelyKeyCombos buffer keySize =
    let chunks = buffer |> Array.chunkBySize keySize
    let transpose (chunks: 'a [][]) offset =
        chunks |> Array.where (fun c -> offset < c.Length) |> Array.map (fun c -> c.[offset])
    let transposedChunks = Array.init keySize (transpose chunks)
    let findLikelyKeyChars transposed =
        transposed
        |> brute'
        |> Seq.where (snd >> isLikelyMatch)
        |> Seq.map (fun (key,text) -> (bytesToString [|key|]))
        |> List.ofSeq
    transposedChunks
    |> Seq.map findLikelyKeyChars
    |> Seq.where (not << List.isEmpty)
    |> List.ofSeq
        
let possibleKeyCombos =
    keySizes
    |> Seq.map (findLikelyKeyCombos repeatKeyCryptBytes)
    |> Seq.where (not << List.isEmpty)

let printPossibleKeyCombos possibleKeys =
    for possibleKeyCombos in possibleKeys do
        cartesian possibleKeyCombos |> Seq.map (String.concat "") |> Seq.iter (printfn "%s")

printPossibleKeyCombos possibleKeyCombos

let keyBytes = "Terminator X: Bring the noise".ToCharArray() |> Array.map byte
let repeatedKey = repeatKey repeatKeyCryptBytes.Length keyBytes
let decrypted =
    xorBytes repeatKeyCryptBytes repeatedKey
    |> Array.ofSeq
    |> Text.Encoding.ASCII.GetString

// Challenge 7

let aesBytes = IO.File.ReadAllLines(__SOURCE_DIRECTORY__ + "/Challenge7.txt") |> String.concat "" |> Convert.FromBase64String
open System.Security.Cryptography
let decrypt key =
    use aes = new AesManaged()
    aes.Mode <- CipherMode.ECB
    aes.Key <- stringToBytes key
    let decryptor = aes.CreateDecryptor(aes.Key, aes.IV)
    use mem = new IO.MemoryStream(aesBytes)
    use decryptStream = new CryptoStream(mem, decryptor, CryptoStreamMode.Read)
    use readStream = new IO.StreamReader(decryptStream)
    readStream.ReadToEnd()
    
decrypt "YELLOW SUBMARINE"

// Challenge 8

let hexLines = IO.File.ReadAllLines(__SOURCE_DIRECTORY__ + "/Challenge8.txt") |> Array.map hexToBytes
hexLines |> Array.map (Array.chunkBySize 16 >> Array.distinct >> Array.length) |> Seq.iteri (printfn "%d: %A") // line 133 has only 7/10 distinct blocks
