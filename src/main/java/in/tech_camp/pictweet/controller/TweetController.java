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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import in.tech_camp.pictweet.custom_user.CustomUserDetail;
import in.tech_camp.pictweet.entity.TweetEntity;
import in.tech_camp.pictweet.form.SearchForm;
import in.tech_camp.pictweet.form.TweetForm;
import in.tech_camp.pictweet.repository.TweetRepository;
import in.tech_camp.pictweet.repository.UserRepository;
import in.tech_camp.pictweet.validation.ValidationOrder;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/tweets")
@AllArgsConstructor
public class TweetController {
  private final TweetRepository tweetRepository;

  private final UserRepository userRepository;

  //全ツイートを取得し、レスポンスとして返す。
  @GetMapping("/")
  public List<TweetEntity> showIndex(Model model) {
        //ツイートデータ全取得
        List<TweetEntity> tweets = tweetRepository.findAll();
        // SearchForm searchForm = new SearchForm();
        // model.addAttribute("tweets", tweets);
        // model.addAttribute("searchForm", searchForm);
        return tweets;
  }

  //新規ツイート作成処理
  @PostMapping("/")
  public ResponseEntity<?> createTweet(@RequestBody @Validated(ValidationOrder.class) TweetForm tweetForm,
                            BindingResult result, 
                            @AuthenticationPrincipal CustomUserDetail currentUser) {

    //エラーが存在した場合
    if (result.hasErrors()) {
      List<String> errorMessages = result.getAllErrors().stream()
              .map(DefaultMessageSourceResolvable::getDefaultMessage)
              .collect(Collectors.toList());
      return ResponseEntity.badRequest().body(Map.of("messages", errorMessages));
    }

    TweetEntity tweet = new TweetEntity();
    tweet.setUser(userRepository.findById(currentUser.getId()));
    tweet.setText(tweetForm.getText());
    tweet.setImage(tweetForm.getImage());
      
    try {
      //ツイートデータ挿入
      tweetRepository.insert(tweet);
      return ResponseEntity.ok().body(tweet);
    } catch (Exception e) {
      System.out.println("エラー：" + e);
      return ResponseEntity.internalServerError().body(Map.of("messages", List.of("Internal Server Error")));
    }

  }

  //ツイート詳細画面
  @GetMapping("/{tweetId}")
  public ResponseEntity<TweetEntity> showTweetDetail(@PathVariable("tweetId") Integer tweetId) {
    //ツイートデータ取得
    TweetEntity tweet = tweetRepository.findById(tweetId);

    if (tweet == null) {
      return ResponseEntity.notFound().build();
    }

    return ResponseEntity.ok().body(tweet);
  }

  //ツイート削除処理
  @PostMapping("/{tweetId}/delete")
  public ResponseEntity<?> deleteTweet(@PathVariable("tweetId") Integer tweetId) {
    try {
      tweetRepository.deleteById(tweetId);
      return ResponseEntity.ok().body("");
    } catch (Exception e) {
      System.out.println("エラー: " + e);
      return ResponseEntity.internalServerError().body(Map.of("messages", List.of("Internal Server Error")));
    }
  }

  //ツイート更新処理
  @PostMapping("/{tweetId}/update")
  public ResponseEntity<?> updateTweet(@RequestBody @Validated(ValidationOrder.class) TweetForm tweetForm,
                            BindingResult result,
                            @PathVariable("tweetId") Integer tweetId) {

    //tweetFormにエラーがあった場合
    if (result.hasErrors()) {
      List<String> errorMessages = result.getAllErrors().stream()
              .map(DefaultMessageSourceResolvable::getDefaultMessage)
              .collect(Collectors.toList());
              return ResponseEntity.badRequest().body(Map.of("messages", errorMessages));
    }

    //tweet取得
    TweetEntity tweet = tweetRepository.findById(tweetId);
    //更新値セット
    tweet.setText(tweetForm.getText());
    tweet.setImage(tweetForm.getImage());

    try {
      //tweet更新
      tweetRepository.update(tweet);
      return ResponseEntity.ok().body(tweet);
    } catch (Exception e) {
      System.out.println("エラー：" + e);
      return ResponseEntity.internalServerError().body(Map.of("messages", List.of("Internal Server Error")));
    }

  }
  
  //ツイート検索処理
  @GetMapping("/search")
  public ResponseEntity<List<TweetEntity>> searchTweets(@RequestParam("query") String query) {
      List<TweetEntity> tweets = tweetRepository.findByTextContaining(query);
      return ResponseEntity.ok().body(tweets);
    
  }

  // @GetMapping("/tweets/{tweetId}/edit")
  // public String editTweet(@PathVariable("tweetId") Integer tweetId, Model model) {
  //   TweetEntity tweet = tweetRepository.findById(tweetId);

  //   TweetForm tweetForm = new TweetForm();
  //   tweetForm.setText(tweet.getText());
  //   tweetForm.setImage(tweet.getImage());

  //   model.addAttribute("tweetForm", tweetForm);
  //   model.addAttribute("tweetId", tweetId);
  //   return "tweets/edit";
  // }

  // @PostMapping("/tweets/{tweetId}/update")
  // public String updateTweet(@ModelAttribute("tweetForm") @Validated(ValidationOrder.class) TweetForm tweetForm,
  //                           BindingResult result,
  //                           @PathVariable("tweetId") Integer tweetId,
  //                           Model model) {

  //   if (result.hasErrors()) {
  //     List<String> errorMessages = result.getAllErrors().stream()
  //             .map(DefaultMessageSourceResolvable::getDefaultMessage)
  //             .collect(Collectors.toList());
  //     model.addAttribute("errorMessages", errorMessages);

  //     model.addAttribute("tweetForm", tweetForm);
  //     model.addAttribute("tweetId", tweetId);
  //     return "tweets/edit";
  //   }

  //   TweetEntity tweet = tweetRepository.findById(tweetId);
  //   tweet.setText(tweetForm.getText());
  //   tweet.setImage(tweetForm.getImage());

  //   try {
  //     tweetRepository.update(tweet);
  //   } catch (Exception e) {
  //     System.out.println("エラー：" + e);
  //     return "redirect:/";
  //   }

  //   return "redirect:/";
  // }

  // @GetMapping("/tweets/{tweetId}")
  // public String showTweetDetail(@PathVariable("tweetId") Integer tweetId, Model model) {
  //     TweetEntity tweet = tweetRepository.findById(tweetId);
  //     CommentForm commentForm = new CommentForm();
  //     model.addAttribute("tweet", tweet);
  //     model.addAttribute("commentForm", commentForm);
  //     model.addAttribute("comments",tweet.getComments());
  //     return "tweets/detail";
  // }

  // @GetMapping("/tweets/search")
  // public String searchTweets(@ModelAttribute("searchForm") SearchForm searchForm, Model model) {
  //   List<TweetEntity> tweets = tweetRepository.findByTextContaining(searchForm.getText());
  //   model.addAttribute("tweets", tweets);
  //   model.addAttribute("searchForm", searchForm);
  //   return "tweets/search";
  // }
}
