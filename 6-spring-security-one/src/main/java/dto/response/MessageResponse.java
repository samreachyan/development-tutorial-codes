package dto.response;


public class MessageResponse {
    private String errorMessage;

    public MessageResponse () {

    }

    public MessageResponse(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
}
