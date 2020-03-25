import Cocoa

let user = "valeriy.van@enote.com"

func shellTask(_ url: URL, arguments: [String], environment: [String : String]) throws -> (output: String?, error: String?) {
    let task = Process()
    task.executableURL = url
    task.arguments =  arguments
    task.environment = environment

    let outputPipe = Pipe()
    let errorPipe = Pipe()

    task.standardOutput = outputPipe
    task.standardError = errorPipe
    try task.run()
    task.waitUntilExit()
    
    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(decoding: outputData, as: UTF8.self)

    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
    let error = String(decoding: errorData, as: UTF8.self)

    return (output: output, error: error)
}

func pythonPutRecord(counter: Int = 1, user: String = user, collection: String = "TestCollection" /* No spaces here! Seems to be case insensitive! */) {
    var counter = counter
    if counter <= 0 {
        counter = 1
    }

    // python3 syncclient/main.py --user valeriy.van@enote.com put_record "test" '{"id":"my-entry-2", "payload":"This is payload"}'

    let pythonInterpreterURL = URL(fileURLWithPath: "/usr/local/bin/python3")
    let pythonScript =  "syncclient/main.py"

    let payload = "This is payload for entry \(counter) " + String(repeating: "a", count: counter)
    let entry = """
    {"id":"my-entry-\(counter)", "payload":\"\(payload)\"}
    """
    let arguments = [pythonScript, "--user", user, "put_record", collection, entry ]
    print("Size of payload ", payload.utf8.count, " bytes")
    //print(arguments)
    //print(entry)

    var environment = ProcessInfo.processInfo.environment
    environment["FXA_SERVER_URL"] = "https://api.accounts.fxa.enote.net"
    environment["TOKENSERVER_URL"] = "https://sync.fxa.enote.net"
    do {
        let result = try shellTask(pythonInterpreterURL, arguments: arguments, environment: environment)
        if let output = result.output {
            print(output)
        }
        if let error = result.error {
            print(error)
        }
    } catch let error {
        print("Unexpected error:\(error)")
    }
}

for i in 0..<100_000 {
    let collection = "c-" + String(i)
    for j in 200_000..<200_010 { // 10 records each greater than 200K
        autoreleasepool {
            pythonPutRecord(counter: j, user: user, collection: collection)
        }
    }
}
