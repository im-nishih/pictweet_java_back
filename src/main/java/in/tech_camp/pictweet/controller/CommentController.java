package in.tech_camp.pictweet.controller;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import in.tech_camp.pictweet.custom_user.CustomUserDetail;
import in.tech_camp.pictweet.entity.CommentEntity;
import in.tech_camp.pictweet.entity.TweetEntity;
import in.tech_camp.pictweet.form.CommentForm;
import in.tech_camp.pictweet.repository.CommentRepository;
import in.tech_camp.pictweet.repository.TweetRepository;
import in.tech_camp.pictweet.repository.UserRepository;
import in.tech_camp.pictweet.validation.ValidationOrder;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/tweets/{tweetId}/comment")
@AllArgsConstructor
public class CommentController {

  private final CommentRepository commentRepository;

  private final UserRepository userRepository;

  private final TweetRepository tweetRepository;

  @PostMapping("/")
  public ResponseEntity<?> createComment(@PathVariable("tweetId") Integer tweetId, 
                            @RequestBody @Validated(ValidationOrder.class) CommentForm commentForm,
                            BindingResult result,
                            @AuthenticationPrincipal CustomUserDetail currentUser, Model model) {

    TweetEntity tweet = tweetRepository.findTweetById(tweetId);

    if (result.hasErrors()) {
      List<String> errorMessages = result.getAllErrors().stream()
              .map(DefaultMessageSourceResolvable::getDefaultMessage)
              .collect(Collectors.toList());
      return ResponseEntity.badRequest().body(Map.of("messages", errorMessages));
    }

    CommentEntity comment = new CommentEntity();
    comment.setText(commentForm.getText());
    comment.setTweet(tweet);
    comment.setUser(userRepository.findUserById(currentUser.getId()));

    try {
      commentRepository.insert(comment);
      return ResponseEntity.ok().body(comment);
    } catch (Exception e) {
      System.out.println("エラー：" + e);
      return ResponseEntity.internalServerError().body(Map.of("messages", List.of("Internal Server Error")));
    }
  }


  // @PostMapping("/tweets/{tweetId}/comment")
  // public String createComment(@PathVariable("tweetId") Integer tweetId, 
  //                           @ModelAttribute("commentForm") @Validated(ValidationOrder.class) CommentForm commentForm,
  //                           BindingResult result,
  //                           @AuthenticationPrincipal CustomUserDetail currentUser, Model model) {

  //   TweetEntity tweet = tweetRepository.findById(tweetId);

  //   if (result.hasErrors()) {
  //       model.addAttribute("errorMessages", result.getAllErrors());
  //       model.addAttribute("tweet", tweet);
  //       model.addAttribute("commentForm", commentForm);
  //       return "tweets/detail";
  //   }

  //   CommentEntity comment = new CommentEntity();
  //   comment.setText(commentForm.getText());
  //   comment.setTweet(tweet);
  //   comment.setUser(userRepository.findById(currentUser.getId()));

  //   try {
  //     commentRepository.insert(comment);
  //   } catch (Exception e) {
  //     model.addAttribute("tweet", tweet);
  //     model.addAttribute("commentForm", commentForm);
  //     System.out.println("エラー：" + e);
  //     return "tweets/detail";
  //   }

  //   return "redirect:/tweets/" + tweetId;
  // }
}

