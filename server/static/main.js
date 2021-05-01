
// default command shel path
var path = "C:\\Windows\\system32";

var greetings = ' \n[[;#ff0;#000] * Shell is not interactive, please be careful what you execute]\n' +
                '[[;#ff0;#000] * Command execution timeout is set to 30 seconds]\n\n';

function term_get_prompt()
{
    // cmd.exe alike command shell prompt   
    return path + "> ";
}

function term_init(request_url, client_id)
{
    // initialize jquery terminal
    var term = $("#shell-output").terminal(function(command, term) 
    {    
        //
        // command handler code
        //
        if (command.length == 0)
        {
            return;
        }

        term.pause();    

        function error_handler(xhr, status, exception)
        {            
            var message = exception || xhr.statusText;

            // some error occurred
            term.echo("\n[[;#f00;#000]Error while executing command:\n" + message + "]\n");
        }

        function data_handler(data)
        {    
            // parse command shell output to get data and current path  
            var m = /{{{\+ \r\n(.+)\r\n\+}}}\r\n/g.exec(data);
            if (m != null)
            {
                path = m[1];
                data = data.split(m[0]).join("");

                // update prompt
                term.set_prompt(term_get_prompt());
            }

            // print command output into the terminal
            term.echo(data);
            term.resume();
        }

        // construct an actual command to execute
        command = path.split("\\")[0] + " & cd \"" + path + "\" & " + command + " & echo {{{+ & cd & echo +}}}";

        // send command to the client
        $.ajax({    type: "POST", url: request_url, 
                    data: { "id": client_id, "c": command }, 
                 success: data_handler, 
                   async: false 

               }).fail(error_handler);    

    }, { greetings: greetings, prompt: term_get_prompt(), exit: false });
}
