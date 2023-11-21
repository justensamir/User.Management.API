namespace User.Management.API.Models.DTOs
{
    public class EmailRequirements
    {
        public string action { get; }
        public string controller { get; }
        public string email { get; }
        public string subject { get; }
        public string content { get; }

        public EmailRequirements(string email, string subject, string content) 
        {
            this.email = email;
            this.subject = subject;
            this.content = content;
        }
        
        public EmailRequirements(string action, string controller, string email, string subject, string content) 
        {
            this.action = action;
            this.controller = controller;
            this.email = email;
            this.subject = subject;
            this.content = content;
        }
    }

}
